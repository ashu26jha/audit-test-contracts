from uuid import UUID

from fastapi import HTTPException
from langfuse.decorators import langfuse_context, observe

from api.v1.audit_agent.helpers.payment_handler import PaymentHandler
from api.v1.audit_agent.helpers.scan_initializer import ScanInitializer
from api.v1.audit_agent.helpers.task_manager import TaskManager
from api.v1.audit_agent.schema import AuditAgentRequest, ScanContext
from api.v1.common.docs_helpers import format_docs_for_prompt
from api.v1.common.result_processor import ResultProcessor
from api.v1.common.setup_environment import cleanup_environment, setup_environment
from api.v1.github.helpers.github_api_client import GitHubAPIClient
from api.v1.github.service import GitHubService
from api.v1.payments.helpers.credits import CreditHelper
from api.v1.utilities.pdf.service import generate_and_send_pdf_from_scan
from core.db.connection import close_database, huey, init_database
from core.db.repositories.docs import DocsRepository
from core.db.repositories.scan import ScanRepository
from core.db.repositories.user import UserRepository
from core.models.scan import Scan
from core.models.user import User
from core.utils.email_utils import send_error_email
from core.utils.logger import logger
from core.utils.profiles import Profiles
from core.utils.validate import validate_free_scan_limit, validate_subscription_limits

github_service = GitHubService()
github_api_client = GitHubAPIClient()


class AuditAgentService:
    @staticmethod
    async def create_scan(
        scan_id: UUID,
        user: User,
        request: AuditAgentRequest,
    ):
        initializer = ScanInitializer(user, request, scan_id)
        try:
            # Validation
            is_subscription_scan = not user.is_free

            if not is_subscription_scan:
                free_scan_status = await validate_free_scan_limit(user.githubId)
                if not free_scan_status.is_allowed:
                    raise HTTPException(
                        status_code=400,
                        detail="Free scan limit reached. Please wait for the next available scan or upgrade your subscription.",
                    )

            await initializer.validate_request()

            # Format docs if provided and user is a subscriber
            formatted_docs = None
            if request.docs and is_subscription_scan and user.is_enterprise:
                await DocsRepository.store_docs(
                    repository_url=request.repositoryURL,
                    user_id=user.githubId,
                    docs=request.docs,
                )

                # Get repository info for readme content
                owner, repo = github_api_client.parse_github_url(request.repositoryURL)

                # Format docs with actual readme content
                formatted_docs = await format_docs_for_prompt(
                    request.docs,
                    user.accessToken,
                    owner,
                    repo,
                    request.branchName,
                )

            # Fetch repository info
            await initializer.fetch_repository_info()

            # Create scan record
            scan_number = await Scan.get_next_scan_number(user.githubId)
            await initializer.create_scan_record(scan_number)

            # Fetch commit hash
            await initializer.fetch_commit_hash()

            # Calculate priority based on user type
            if user.is_enterprise:
                priority = 1  # Highest priority
            elif user.is_pro:
                priority = 5  # Medium priority
            else:
                priority = 10  # Lowest priority (default)

            # Queue the task with Huey
            perform_audit_agent_background(
                scan_id=str(scan_id),
                user_id=str(user.githubId),
                user_email=user.email,
                user_access_token=user.accessToken,
                scan_number=scan_number,
                request_dict=request.model_dump(),
                is_subscription_scan=is_subscription_scan,
                formatted_docs=formatted_docs if formatted_docs else None,
                priority=priority,
            )

        except HTTPException:
            raise
        except Exception as e:
            logger.exception(f"Unexpected error during scan initiation: {str(e)}")
            await ScanRepository.update_scan_failure(scan_id, "Failed to initiate audit scan")
            await send_error_email(user.email, scan_id)
            raise HTTPException(status_code=500, detail="Failed to initiate audit scan") from e


@huey.task(retries=3, retry_delay=60, priority=10)
def perform_audit_agent_background(
    scan_id: str,
    user_id: str,
    user_email: str,
    user_access_token: str,
    scan_number: int,
    request_dict: dict,
    is_subscription_scan: bool,
    formatted_docs: dict = None,
):
    """
    The main Huey task that executes the audit scan
    """
    import asyncio
    import os

    # Set environment variable to indicate we're in a Huey worker
    os.environ["HUEY_WORKER"] = "1"

    # Create a new event loop using the default event loop policy
    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)

    try:
        # Initialize database first, before any other async operations
        loop.run_until_complete(init_database())

        @observe(name="audit_agent_background")
        async def _async_perform_scan():
            initializer = None
            try:
                # Convert request dict back to AuditAgentRequest
                request = AuditAgentRequest(**request_dict)

                # Create context
                context = ScanContext(
                    scan_id=UUID(scan_id),
                    user_id=user_id,
                    user_email=user_email,
                    user_access_token=user_access_token,
                    scan_number=scan_number,
                    repository_url=request.repositoryURL,
                    branch_name=request.branchName,
                    contract_files=request.contractFiles,
                    is_subscription_scan=is_subscription_scan,
                    formatted_docs=formatted_docs,
                )

                # Create a User object for the initializer
                user = await UserRepository.get_by_github_id(user_id)

                # Create initializer with the actual User object
                initializer = ScanInitializer(user, request, UUID(scan_id))

                logger.info(f"Starting background audit scan with ID: {context.scan_id}")

                try:
                    # Create initial payment record
                    payment_handler = PaymentHandler(context)
                    await payment_handler.initialize_payment()

                    # Deduct credit
                    if context.is_subscription_scan:
                        await CreditHelper.deduct_credit(
                            context.user_id, context.scan_id, context.repository_url
                        )

                    await ScanRepository.update_scan_progress(context.scan_id, 5)

                    # Setup environment
                    await initializer.clone_repository()

                    # Flatten contracts & Count lines of code
                    flattened_contracts = await initializer.flatten_contracts()
                    lines_of_code = await initializer.count_lines_of_code(flattened_contracts)

                    # Let validation errors bubble up to main exception handler
                    await validate_subscription_limits(
                        context.user_id, context.contract_files, lines_of_code.total_lines
                    )

                    # Update scan status to 'in_progress'
                    await ScanRepository.update_scan_status(context.scan_id, "in_progress")
                    await ScanRepository.update_scan_progress(context.scan_id, 12)

                    # Set up the environment directly in the worker process
                    setup_result = None
                    try:
                        setup_result = await setup_environment(
                            context.repository_url,
                            initializer.repo_dir,
                            context.user_access_token,
                            context.branch_name,
                            context.contract_files,
                        )
                        # Update progress after successful setup (25%)
                        await ScanRepository.update_scan_progress(context.scan_id, 25)
                    except Exception as e:
                        logger.error(f"Environment setup failed: {str(e)}")
                        # Continue with setup_result as None

                    # Initialize TaskManager
                    task_manager = TaskManager(
                        context=context,
                        flattened_contracts=flattened_contracts,
                        setup_result=setup_result,
                        detected_profile=Profiles.DEFAULT,
                    )

                    # Initialize scan and detectors
                    await task_manager.initialize_scan()

                    # Start tasks (will skip Slither if setup_result is None)
                    await task_manager.start_tasks()

                    # Gather and process results
                    results = await task_manager.gather_results()

                    combined_findings = results["combined_findings"]
                    summary_result = results["summary_result"]
                    detected_type = results["detected_type"]

                    # Process results using ResultProcessor
                    result_processor = ResultProcessor(
                        scan_id=context.scan_id,
                        user_id=context.user_id,
                        contract_files=context.contract_files,
                        combined_findings=combined_findings,
                        flattened_contracts=flattened_contracts,
                        summary_result=summary_result,
                        detected_type=detected_type,
                    )
                    await result_processor.process_results()
                    total_findings_after_dedup = result_processor.get_total_findings()

                    langfuse_context.update_current_trace(session_id=str(context.scan_id))

                    # Handle payment processing using PaymentHandler
                    payment_handler = PaymentHandler(context, total_findings_after_dedup)
                    await payment_handler.finalize_payment()

                    # Update scan status to 'completed' and include total_findings
                    await ScanRepository.update_scan_status(
                        context.scan_id, "completed", total_findings_after_dedup
                    )

                    # Generate PDF without blocking scan completion
                    if context.user_email:
                        try:
                            user = await UserRepository.get_by_github_id(context.user_id)
                            await generate_and_send_pdf_from_scan(user, context.scan_id)
                        except Exception as e:
                            logger.error(f"Failed to generate PDF: {str(e)}")
                            # Don't fail the scan if PDF generation fails
                    else:
                        logger.warning(f"User {context.user_id} does not have an email address.")

                    logger.info(f"Completed audit scan with ID: {context.scan_id}")

                    return results
                except HTTPException as e:
                    error_msg = f"Error in audit scan {context.scan_id}: {str(e)}"
                    logger.exception(error_msg)
                    await ScanRepository.update_scan_failure(context.scan_id, e.detail)
                    if context.is_subscription_scan:
                        await CreditHelper.refund_credit(context.user_id, context.scan_id)
                    await send_error_email(context.user_email, context.scan_id)
                    raise
                except Exception as e:
                    error_msg = f"Unexpected error: {str(e)}"
                    logger.exception(error_msg)
                    await ScanRepository.update_scan_failure(context.scan_id, error_msg)
                    if context.is_subscription_scan:
                        await CreditHelper.refund_credit(context.user_id, context.scan_id)
                    await send_error_email(context.user_email, context.scan_id)
                    raise HTTPException(status_code=500, detail=error_msg) from e
            except Exception as e:
                logger.exception(f"Error in async scan execution: {str(e)}")
                raise
            finally:
                if (
                    initializer
                    and hasattr(initializer, "temp_dir")
                    and hasattr(initializer, "repo_dir")
                ):
                    await cleanup_environment(initializer.temp_dir, initializer.repo_dir)
                    await close_database()

        try:
            # Run the async function in the event loop
            return loop.run_until_complete(_async_perform_scan())
        except Exception as e:
            logger.exception(f"Error in Huey task: {str(e)}")
            raise
        finally:
            try:
                # Run all remaining tasks to completion
                pending = asyncio.all_tasks(loop)
                loop.run_until_complete(asyncio.gather(*pending))
            except Exception as e:
                logger.error(f"Error during task cleanup: {str(e)}")
            finally:
                loop.close()
                asyncio.set_event_loop(None)

    except Exception as e:
        logger.exception(f"Error in Huey task: {str(e)}")
        raise
