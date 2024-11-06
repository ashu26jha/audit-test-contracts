import os
import shutil
from datetime import datetime, timezone
from typing import List, Optional
from uuid import UUID

from fastapi import BackgroundTasks, HTTPException
from langfuse.decorators import langfuse_context, observe

from api.v1.helpers.audit_helpers import update_scan_failure
from api.v1.helpers.setup_environment_helpers import setup_environment
from api.v1.models.user import User
from api.v1.schemas import audit_agent_schema
from api.v1.schemas.fuzzer_schema import SetupResult
from api.v1.services import scan_history_service
from api.v1.services.audit_services.payment_handler import PaymentHandler
from api.v1.services.audit_services.result_processor import ResultProcessor
from api.v1.services.audit_services.scan_initializer import ScanInitializer
from api.v1.services.audit_services.task_manager import TaskManager
from api.v1.services.github_service import GitHubService
from common.email_utils import send_completion_email
from common.logger import logger
from common.profiles import Profiles

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
        await initializer.validate_request()

        # Clone repository
        await initializer.clone_repository()

        # Fetch repository info
        await initializer.fetch_repository_info()

        # Create scan record
        await initializer.create_scan_record()

        # Fetch commit hash
        await initializer.fetch_commit_hash()

        # Flatten contracts
        flattened_contracts = await initializer.flatten_contracts()

        # Count lines of code
        await initializer.count_lines_of_code(flattened_contracts)

        # Start the background task
        background_tasks.add_task(
            perform_audit_agent_background,
            user,
            scan_id,
            flattened_contracts,
            request.repositoryURL,
            user.accessToken,
            request.contractFiles,
            initializer.branch_name,
            initializer.temp_dir,
            initializer.repo_dir,
        )

    except HTTPException:
        raise
    except Exception as e:
        logger.exception(f"Unexpected error during scan initiation: {str(e)}")
        await update_scan_failure(user.email, scan_id, "Failed to initiate audit scan")
        raise HTTPException(status_code=500, detail="Failed to initiate audit scan")


@observe()
async def perform_audit_agent_background(
    user: User,
    scan_id: UUID,
    flattened_contracts: str,
    repositoryURL: str,
    access_token: str,
    selected_contracts: List[str],
    branch_name: str,
    temp_dir: str,
    repo_dir: str,
):
    logger.info(f"Starting background audit scan with ID: {scan_id}")

    if not temp_dir or not repo_dir:
        logger.error("Temporary directory or repository directory is missing.")
        await update_scan_failure(user.email, scan_id, "Internal error: Missing directories.")
        return

    setup_result: Optional[SetupResult] = None
    cleanup_required = False

    try:
        # Update scan status to 'in_progress'
        await scan_history_service.update_scan_status(scan_id, "in_progress")

        # Attempt to set up the environment using the existing repo_dir
        try:
            setup_result = await setup_environment(
                repositoryURL,
                repo_dir,
                access_token,
                branch_name,
            )
        except Exception:
            setup_result = None

        # Initialize TaskManager
        task_manager = TaskManager(
            scan_id=scan_id,
            flattened_contracts=flattened_contracts,
            selected_contracts=selected_contracts,
            setup_result=setup_result,
            detected_profile=Profiles.DEFAULT,
        )

        # Initialize scan and detectors
        await task_manager.initialize_scan()

        # Start tasks
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
            summary_result=summary_result,
            detected_type=detected_type,
        )
        await result_processor.process_results()
        total_findings_after_dedup = result_processor.get_total_findings()

        langfuse_context.update_current_trace(session_id=str(scan_id))

        # Handle payment processing using PaymentHandler
        payment_handler = PaymentHandler(user, scan_id, total_findings_after_dedup)
        await payment_handler.process_payment()

        # Update scan status to 'completed' and include total_findings
        await scan_history_service.update_scan_status(
            scan_id, "completed", total_findings_after_dedup
        )

        logger.info(f"Completed audit scan with ID: {scan_id}")

        if user.email:
            scan = await scan_history_service.get_scan(scan_id)
            await send_completion_email(
                to_email=user.email,
                scan_id=str(scan_id),
                scan_number=scan.scan_number,
                total_findings=total_findings_after_dedup,
            )
        else:
            logger.warning(f"User {user.id} does not have an email address.")

    except Exception as e:
        cleanup_required = True
        logger.exception(f"Error in audit scan {scan_id}: {str(e)}")
        await update_scan_failure(user.email, scan_id, "An error occurred during the audit scan.")
    finally:
        # Clean up temporary directory if it exists
        try:
            if os.path.exists(temp_dir):
                shutil.rmtree(temp_dir)
                logger.info(f"Successfully cleaned up temporary directory: {temp_dir}")
        except Exception as e:
            logger.exception(f"Failed to clean up temporary directory {temp_dir}: {str(e)}")

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
