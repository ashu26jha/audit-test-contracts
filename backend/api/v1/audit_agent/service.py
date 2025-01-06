from typing import Optional
from uuid import UUID

from fastapi import BackgroundTasks, HTTPException
from langfuse.decorators import langfuse_context, observe

from api.v1.audit_agent.helpers.payment_handler import PaymentHandler
from api.v1.audit_agent.helpers.result_processor import ResultProcessor
from api.v1.audit_agent.helpers.scan_initializer import ScanInitializer
from api.v1.audit_agent.helpers.task_manager import TaskManager
from api.v1.audit_agent.schema import AuditAgentRequest, ScanContext
from api.v1.common.docs_helpers import format_docs_for_prompt
from api.v1.common.setup_environment import cleanup_environment, setup_environment
from api.v1.github.helpers.github_api_client import GitHubAPIClient
from api.v1.github.service import GitHubService
from api.v1.payments.helpers.credits import CreditHelper
from core.db.repositories.docs import DocsRepository
from core.db.repositories.scan import ScanRepository
from core.models.scan import Scan
from core.models.user import User
from core.schemas.audit_agent_schema import SetupResult
from core.utils.email_utils import send_completion_email, send_error_email
from core.utils.logger import logger
from core.utils.profiles import Profiles
from core.utils.validate import validate_subscription_limits

github_service = GitHubService()
github_api_client = GitHubAPIClient()


class AuditAgentService:
    @staticmethod
    async def create_scan(
        scan_id: UUID,
        user: User,
        request: AuditAgentRequest,
        background_tasks: BackgroundTasks,
    ):
        initializer = ScanInitializer(user, request, scan_id)
        try:
            # Validation
            is_pro_scan = await user.has_active_subscription()
            await initializer.validate_request()

            # Format docs if provided and user is a subscriber
            formatted_docs = None
            if request.docs and is_pro_scan:
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
            await initializer.create_scan_record()

            # Fetch commit hash
            await initializer.fetch_commit_hash()

            # Create scan context
            scan_number = await Scan.get_next_scan_number(user.githubId)
            context = ScanContext(
                scan_id=scan_id,
                user_id=str(user.githubId),
                user_email=user.email,
                user_access_token=user.accessToken,
                scan_number=scan_number,
                repository_url=request.repositoryURL,
                branch_name=request.branchName,
                contract_files=request.contractFiles,
                is_pro_scan=is_pro_scan,
                formatted_docs=formatted_docs,
            )

            # Start initialization in background
            background_tasks.add_task(
                AuditAgentService._perform_scan_initialization,
                context,
                initializer,
                background_tasks,
            )

        except HTTPException:
            raise
        except Exception as e:
            logger.exception(f"Unexpected error during scan initiation: {str(e)}")
            await ScanRepository.update_scan_failure(scan_id, "Failed to initiate audit scan")
            await send_error_email(user.email, scan_id)
            raise HTTPException(status_code=500, detail="Failed to initiate audit scan") from e

    @staticmethod
    async def _perform_scan_initialization(
        context: ScanContext,
        initializer: ScanInitializer,
        background_tasks: BackgroundTasks,
    ):
        try:
            # Create initial payment record
            payment_handler = PaymentHandler(context)
            await payment_handler.initialize_payment()

            # Deduct credit
            if context.is_pro_scan:
                try:
                    await CreditHelper.deduct_credit(
                        context.user_id, context.scan_id, context.repository_url
                    )
                except HTTPException as e:
                    logger.error(f"Failed to deduct credit: {str(e)}")
                    raise e

            # Setup environment
            await initializer.clone_repository()

            # Flatten contracts & Count lines of code
            flattened_contracts = await initializer.flatten_contracts()
            lines_of_code = await initializer.count_lines_of_code(flattened_contracts)

            try:
                await validate_subscription_limits(
                    context.user_id, context.contract_files, lines_of_code.total_lines
                )
            except HTTPException as e:
                logger.error(f"Subscription limits exceeded: {str(e)}")
                await ScanRepository.update_scan_failure(
                    context.scan_id, f"Subscription limit exceeded: {str(e)}"
                )
                await send_error_email(context.user_email, context.scan_id)
                await cleanup_environment(initializer.temp_dir, initializer.repo_dir)
                return

            await ScanRepository.update_scan_progress(context.scan_id, 10)

            # Start the main audit task
            background_tasks.add_task(
                AuditAgentService._perform_audit_agent_background,
                context,
                flattened_contracts,
                initializer.temp_dir,
                initializer.repo_dir,
            )
        except Exception as e:
            logger.exception(f"Error during scan initialization: {str(e)}")
            await ScanRepository.update_scan_failure(
                context.scan_id, "Failed during scan initialization"
            )
            if context.is_pro_scan:
                await CreditHelper.refund_credit(context.user_id, context.scan_id)
            await send_error_email(context.user_email, context.scan_id)
            await cleanup_environment(initializer.temp_dir, initializer.repo_dir)
            raise

    @staticmethod
    @observe()
    async def _perform_audit_agent_background(
        context: ScanContext,
        flattened_contracts: str,
        temp_dir: str,
        repo_dir: str,
    ):
        logger.info(f"Starting background audit scan with ID: {context.scan_id}")

        try:
            if not temp_dir or not repo_dir:
                raise HTTPException(status_code=500, detail="Internal error: Missing directories.")

            setup_result: Optional[SetupResult] = None
            original_temp_dir = temp_dir  # Store for cleanup

            # Update scan status to 'in_progress'
            await ScanRepository.update_scan_status(context.scan_id, "in_progress")

            # Attempt to set up the environment using the existing repo_dir
            setup_result = None
            try:
                setup_result = await setup_environment(
                    context.repository_url,
                    repo_dir,
                    context.user_access_token,
                    context.branch_name,
                    context.scan_id,
                    context.contract_files,
                )
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
                context=context,
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

            if context.user_email:
                # Fetch scan to get scan_number
                scan = await ScanRepository.get_scan(context.scan_id)
                if scan:
                    await send_completion_email(
                        to_email=context.user_email,
                        scan_id=str(context.scan_id),
                        scan_number=scan.scan_number,
                        total_findings=total_findings_after_dedup,
                    )
                else:
                    logger.error(
                        f"Could not find scan with ID {context.scan_id} to send completion email"
                    )
            else:
                logger.warning(f"User {context.user_id} does not have an email address.")

            logger.info(f"Completed audit scan with ID: {context.scan_id}")
        except HTTPException as e:
            error_msg = f"Error in audit scan {context.scan_id}: {str(e)}"
            logger.exception(error_msg)
            await ScanRepository.update_scan_failure(context.scan_id, e.detail)
            if context.is_pro_scan:
                await CreditHelper.refund_credit(context.user_id, context.scan_id)
            await send_error_email(context.user_email, context.scan_id)
            raise

        except Exception as e:
            error_msg = f"Unexpected error: {str(e)}"
            logger.exception(error_msg)
            await ScanRepository.update_scan_failure(context.scan_id, error_msg)
            if context.is_pro_scan:
                await CreditHelper.refund_credit(context.user_id, context.scan_id)
            await send_error_email(context.user_email, context.scan_id)
            raise HTTPException(status_code=500, detail=error_msg) from e
        finally:
            await cleanup_environment(original_temp_dir, repo_dir)
