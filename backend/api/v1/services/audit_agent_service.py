from datetime import datetime, timezone
from typing import List, Optional
from uuid import UUID

from fastapi import BackgroundTasks, HTTPException
from langfuse.decorators import langfuse_context, observe

from api.v1.helpers.audit_helpers import update_scan_failure
from api.v1.helpers.repository_docs_helpers import format_docs_for_prompt, store_repository_docs
from api.v1.helpers.setup_environment_helpers import cleanup_environment, setup_environment
from api.v1.models.user import User
from api.v1.schemas import audit_agent_schema
from api.v1.schemas.fuzzer_schema import SetupResult
from api.v1.services import scan_history_service
from api.v1.services.audit_services.payment_handler import PaymentHandler
from api.v1.services.audit_services.result_processor import ResultProcessor
from api.v1.services.audit_services.scan_initializer import ScanInitializer
from api.v1.services.audit_services.task_manager import TaskManager
from api.v1.services.github_service import GitHubService
from api.v1.services.payments.stripe_subscription_service import deduct_credit
from common.email_utils import send_completion_email
from common.logger import logger
from common.profiles import Profiles
from common.validate import validate_subscription_limits

github_service = GitHubService()


async def initiate_scan(
    scan_id: UUID,
    user: User,
    request: audit_agent_schema.AuditAgentRequest,
    background_tasks: BackgroundTasks,
):
    initializer = ScanInitializer(user, request, scan_id)
    try:
        # Validation
        is_pro_scan = await initializer.validate_request()

        # Format docs if provided and user is a subscriber
        formatted_docs = None
        if request.docs and is_pro_scan:
            await store_repository_docs(
                repository_url=request.repositoryURL,
                user_id=user.githubId,
                docs=request.docs,
            )

            # Get repository info for readme content
            owner, repo = github_service.github_helpers.parse_github_url(request.repositoryURL)

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

        # Start initialization in background
        background_tasks.add_task(
            _perform_scan_initialization,
            user,
            scan_id,
            is_pro_scan,
            request,
            initializer,
            formatted_docs,
            background_tasks,
        )

    except HTTPException:
        raise
    except Exception as e:
        logger.exception(f"Unexpected error during scan initiation: {str(e)}")
        await update_scan_failure(user.email, scan_id, "Failed to initiate audit scan")
        raise HTTPException(status_code=500, detail="Failed to initiate audit scan") from e


async def _perform_scan_initialization(
    user: User,
    scan_id: UUID,
    is_pro_scan: bool,
    request: audit_agent_schema.AuditAgentRequest,
    initializer: ScanInitializer,
    formatted_docs: Optional[str],
    background_tasks: BackgroundTasks,
):
    try:
        # Deduct credit
        if is_pro_scan:
            await deduct_credit(user.githubId, scan_id, request.repositoryURL)

        # Clone repository
        await initializer.clone_repository()

        # Flatten contracts & Count lines of code
        flattened_contracts = await initializer.flatten_contracts()
        lines_of_code = await initializer.count_lines_of_code(flattened_contracts)

        try:
            await validate_subscription_limits(
                user, request.contractFiles, lines_of_code["total_lines"]
            )
        except HTTPException as e:
            logger.error(f"Subscription limits exceeded: {str(e)}")
            await update_scan_failure(user.email, scan_id, f"Subscription limit exceeded: {str(e)}")
            return

        await scan_history_service.update_scan_progress(scan_id, 10)

        # If all initialization steps succeed, start the main audit task
        background_tasks.add_task(
            _perform_audit_agent_background,
            user,
            scan_id,
            is_pro_scan,
            flattened_contracts,
            request.repositoryURL,
            request.branchName,
            request.contractFiles,
            formatted_docs,
            initializer.temp_dir,
            initializer.repo_dir,
        )
    except Exception as e:
        logger.exception(f"Error during scan initialization: {str(e)}")
        await update_scan_failure(user.email, scan_id, "Failed during scan initialization")
        await initializer.cleanup()
        raise  # Re-raise to ensure the task stops


@observe()
async def _perform_audit_agent_background(
    user: User,
    scan_id: UUID,
    is_pro_scan: bool,
    flattened_contracts: str,
    repository_url: str,
    branch_name: str,
    selected_contracts: List[str],
    formatted_docs: Optional[str],
    temp_dir: str,
    repo_dir: str,
):
    logger.info(f"Starting background audit scan with ID: {scan_id}")

    if not temp_dir or not repo_dir:
        logger.error("Temporary directory or repository directory is missing.")
        await update_scan_failure(user.email, scan_id, "Internal error: Missing directories.")
        return

    setup_result: Optional[SetupResult] = None
    original_temp_dir = temp_dir  # Store for cleanup
    cleanup_required = False  # Initialize the flag

    try:
        # Update scan status to 'in_progress'
        await scan_history_service.update_scan_status(scan_id, "in_progress")

        # Attempt to set up the environment using the existing repo_dir
        setup_result = None
        try:
            setup_result = await setup_environment(
                repository_url,
                repo_dir,
                user.accessToken,
                branch_name,
                scan_id,
                selected_contracts,
            )
        except Exception as e:
            logger.error(f"Environment setup failed: {str(e)}")
            # Continue with setup_result as None

        # Initialize TaskManager
        task_manager = TaskManager(
            scan_id=scan_id,
            flattened_contracts=flattened_contracts,
            selected_contracts=selected_contracts,
            docs=formatted_docs,
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
            scan_id=scan_id,
            user_id=str(user.id),
            combined_findings=combined_findings,
            selected_contracts=selected_contracts,
            flattened_contracts=flattened_contracts,
            summary_result=summary_result,
            detected_type=detected_type,
        )
        await result_processor.process_results()
        total_findings_after_dedup = result_processor.get_total_findings()

        langfuse_context.update_current_trace(session_id=str(scan_id))

        # Handle payment processing using PaymentHandler
        payment_handler = PaymentHandler(user, scan_id, is_pro_scan, total_findings_after_dedup)
        await payment_handler.process_payment()

        # Update scan status to 'completed' and include total_findings
        await scan_history_service.update_scan_status(
            scan_id, "completed", total_findings_after_dedup
        )

        if user.email:
            # Fetch scan to get scan_number
            scan = await scan_history_service.get_scan(scan_id)
            if scan:
                await send_completion_email(
                    to_email=user.email,
                    scan_id=str(scan_id),
                    scan_number=scan.scan_number,
                    total_findings=total_findings_after_dedup,
                )
            else:
                logger.error(f"Could not find scan with ID {scan_id} to send completion email")
        else:
            logger.warning(f"User {user.id} does not have an email address.")

        logger.info(f"Completed audit scan with ID: {scan_id}")
    except Exception as e:
        cleanup_required = True
        logger.exception(f"Error in audit scan {scan_id}: {str(e)}")
        await update_scan_failure(user.email, scan_id, "An error occurred during the audit scan.")
    finally:
        await cleanup_environment(original_temp_dir, repo_dir)

        # If there was an error, clean up the scan data
        if cleanup_required:
            await cleanup_failed_scan(scan_id)


async def cleanup_failed_scan(scan_id: UUID):
    """Clean up partial results while preserving detector statuses."""
    try:
        # Reset scan result to initial state but keep findings for debugging
        scan_result = await scan_history_service.get_scan_result(scan_id)
        if scan_result:
            scan_result.info_message = "Scan failed - see detector statuses for details"
            scan_result.completedAt = datetime.now(timezone.utc)
            scan_result.total_findings = 0
            await scan_result.save()

        # Update scan status but preserve detector information
        scan = await scan_history_service.get_scan(scan_id)
        if scan:
            scan.status = "failed"
            scan.completedAt = datetime.now(timezone.utc)
            await scan.save()
    except Exception as e:
        logger.error(f"Failed to cleanup scan {scan_id}: {e}")
