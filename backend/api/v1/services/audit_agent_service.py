import asyncio
import shutil
import tempfile
from datetime import datetime, timezone
from typing import List, Optional
from uuid import UUID

from fastapi import BackgroundTasks, HTTPException

from api.v1.helpers.setup_environment_helpers import setup_environment
from api.v1.models.global_stats import GlobalStats
from api.v1.models.scan import Scan, ScanResult
from api.v1.models.user import User
from api.v1.schemas import audit_agent_schema
from api.v1.schemas.fuzzer_schema import SetupResult
from api.v1.services import (
    context_scan_service,
    flatten_contracts_service,
    fuzzing_service,
    generate_summary_service,
    lines_of_code_service,
    scan_history_service,
    static_analyzer_service,
)
from api.v1.services.github_service import GitHubService
from common import duplicates
from common.logger import logger
from common.profiles import Profiles
from common.validate import (
    validate_contract_files,
    validate_github_url,
    validate_no_in_progress_scans,
    validate_no_unpaid_scans,
    validate_user_has_github_token,
)
from config import settings

github_service = GitHubService()


async def initiate_scan(
    scan_id: UUID,
    user: User,
    request: audit_agent_schema.AuditAgentRequest,
    background_tasks: BackgroundTasks,
):
    try:
        validate_user_has_github_token(user)
        validate_github_url(request.repositoryURL)
        validate_contract_files(request.contractFiles)
        await validate_no_in_progress_scans(user)
        if settings.ENVIRONMENT == "production":
            await validate_no_unpaid_scans(user)

        # Fetch repository info
        repo_info = await github_service.fetch_github_repo_info(
            user.accessToken, request.repositoryURL
        )
        # Get the next scan_id for this user
        scan_number = await Scan.get_next_scan_number(str(user.id))

        # Create and store the new scan with initial status 'pending'
        branch_name = request.branchName if request.branchName else "main"
        new_scan = Scan(
            scan_id=scan_id,
            scan_number=scan_number,
            user_id=str(user.id),
            status="pending",
            startedAt=datetime.now(timezone.utc),
            contractFiles=request.contractFiles,
            repositoryURL=request.repositoryURL,
            repositoryName=repo_info.repo_name,
            branchName=branch_name,
        )
        await scan_history_service.store_scan(new_scan)

        # Create and store an initial empty scan result
        initial_scan_result = ScanResult(
            scan_id=scan_id,
            scan_number=scan_number,
            summary="Scan in progress",
            type=Profiles.NONE,
            total_findings=0,
            findings=[],
        )
        await scan_history_service.store_scan_result(initial_scan_result)

        # Increment global stats (unpaid by default)
        await GlobalStats.increment_scan(status="pending", paid=False, findings=0, lines_of_code=0)

        # Fetch the commit hash using GitHub API
        try:
            commit_hash = await github_service.get_commit_hash(
                user.accessToken, request.repositoryURL, branch_name
            )
        except HTTPException as e:
            # Update scan status to 'failed'
            await scan_history_service.update_scan_status(scan_id, "failed")
            # Update global stats for failed scan
            await GlobalStats.increment_scan(
                status="failed", paid=False, findings=0, lines_of_code=0
            )
            # Update the scan result to reflect the failure
            failed_scan_result = ScanResult(
                scan_id=scan_id,
                scan_number=scan_number,
                summary=f"Scan failed: {e.detail}",
                type=Profiles.NONE,
                total_findings=0,
                findings=[],
            )
            await scan_history_service.store_scan_result(failed_scan_result)
            # Re-raise the exception with additional context
            raise HTTPException(
                status_code=e.status_code,
                detail=f"Failed to fetch commit hash: {e.detail}",
            )

        if not commit_hash:
            await scan_history_service.update_scan_status(scan_id, "failed")
            raise HTTPException(
                status_code=500,
                detail="Failed to fetch commit hash. Check if branch exists.",
            )

        new_scan.commitHash = commit_hash
        await new_scan.save()

        # Flatten contracts and count lines of code
        flattened_contracts = await flatten_contracts_service.flatten_contracts(
            request.repositoryURL, request.contractFiles, user.accessToken, branch_name
        )
        lines_of_code = await lines_of_code_service.count_lines_of_code(flattened_contracts)
        new_scan.linesOfCode = lines_of_code
        await new_scan.save()

        # Start the background task
        background_tasks.add_task(
            perform_audit_agent_background,
            scan_id,
            flattened_contracts,
            request.repositoryURL,
            user.accessToken,
            request.contractFiles,
            branch_name,
        )

    except HTTPException:
        raise
    except Exception as e:
        logger.exception(f"Unexpected error during scan initiation: {str(e)}")
        await GlobalStats.increment_scan(status="failed", paid=False, findings=0, lines_of_code=0)

        # Update scan status to 'failed' if scan exists
        try:
            await scan_history_service.update_scan_status(scan_id, "failed")
            # Also update the scan result to reflect the failure
            failed_scan_result = ScanResult(
                scan_id=scan_id,
                scan_number=scan_number,
                summary="Scan failed to initiate",
                type=Profiles.NONE,
                total_findings=0,
                findings=[],
            )
            await scan_history_service.store_scan_result(failed_scan_result)
        except Exception:
            logger.warning(f"Scan {scan_id} not found when updating status to 'failed'")
        raise HTTPException(status_code=500, detail="Failed to initiate audit scan")


async def perform_audit_agent_background(
    scan_uuid: UUID,
    flattened_contracts: str,
    repositoryURL: str,
    access_token: str,
    selected_contracts: List[str],
    branch_name: str,
):
    logger.info(f"Starting background audit scan with ID: {scan_uuid}")

    temp_dir = tempfile.mkdtemp()
    setup_result: Optional[SetupResult] = None

    try:
        # Update scan status to 'in_progress'
        await scan_history_service.update_scan_status(scan_uuid, "in_progress")

        # Attempt to set up the environment
        try:
            setup_result = await setup_environment(
                repositoryURL,
                temp_dir,
                access_token,
            )
        except Exception as e:
            logger.error(f"Failed to set up environment: {str(e)}")

        # Start summary generation task
        summary_task = asyncio.create_task(
            generate_summary_service.generate_summary(flattened_contracts)
        )

        # If setup_result is available, start static analysis and fuzzing tasks
        static_analysis_task = None
        fuzzing_task = None
        if setup_result:
            static_analysis_task = asyncio.create_task(
                static_analyzer_service.run_static_analyzer(
                    repositoryURL,
                    access_token,
                    selected_contracts,
                    setup_result,
                )
            )
            fuzzing_task = asyncio.create_task(
                fuzzing_service.run_fuzzer(
                    repositoryURL,
                    access_token,
                    selected_contracts,
                    flattened_contracts,
                    setup_result,
                )
            )
        else:
            logger.warning("Skipping static analysis and fuzzing due to setup failure.")

        # Await summary result to proceed with context scan
        try:
            summary_result, detected_type = await summary_task
        except Exception:
            summary_result = "Summary generation failed."
            detected_type = Profiles.NONE

        # Detect profile
        detected_profile = (
            Profiles[detected_type.upper()]
            if detected_type.upper() in Profiles.__members__
            else Profiles.DEFAULT
        )

        # Start context scan task
        context_scan_task = asyncio.create_task(
            context_scan_service.perform_context_scan(
                summary_result, flattened_contracts, detected_profile
            )
        )

        # Gather tasks to await
        tasks_to_await = [context_scan_task]
        if static_analysis_task:
            tasks_to_await.append(static_analysis_task)
        if fuzzing_task:
            tasks_to_await.append(fuzzing_task)

        # Await all tasks concurrently, handling exceptions individually
        results = await asyncio.gather(*tasks_to_await, return_exceptions=True)

        # Initialize findings list
        combined_findings = []

        # Process results
        # Index for results list
        result_index = 0

        # Handle context scan result
        context_scan_result = results[result_index]
        result_index += 1
        if isinstance(context_scan_result, Exception):
            logger.error(f"Context scan failed: {context_scan_result}")
            context_scan_result = []
        combined_findings.extend(context_scan_result)

        # Handle static analysis result
        if static_analysis_task:
            static_analysis_result = results[result_index]
            result_index += 1
            if isinstance(static_analysis_result, Exception):
                logger.error(f"Static analysis failed: {static_analysis_result}")
            else:
                slither_findings = getattr(static_analysis_result.slither_output, "findings", [])
                combined_findings.extend(slither_findings)

        # Handle fuzzing result
        if fuzzing_task:
            fuzzing_result = results[result_index]
            result_index += 1
            if isinstance(fuzzing_result, Exception):
                logger.error(f"Fuzzing failed: {fuzzing_result}")
            else:
                fuzzing_findings = getattr(fuzzing_result.data, "findings", [])
                combined_findings.extend(fuzzing_findings)

        # Remove duplicates from combined findings
        dedup_findings = await duplicates.remove_duplicates(combined_findings)
        total_findings = len(dedup_findings)

        # Update the existing scan result
        scan_result = await scan_history_service.get_scan_result(scan_uuid)
        scan_result.summary = summary_result
        scan_result.type = detected_profile
        scan_result.total_findings = total_findings
        scan_result.findings = dedup_findings
        await scan_result.save()

        # Update scan status to 'completed' and include total_findings
        await scan_history_service.update_scan_status(scan_uuid, "completed", total_findings)

        # Update global stats
        scan = await scan_history_service.get_scan(scan_uuid)
        total_lines = scan.linesOfCode.get("total_lines", 0) if scan.linesOfCode else 0
        await GlobalStats.increment_scan(
            status="completed",
            paid=scan.paid_status,
            findings=total_findings,
            lines_of_code=total_lines,
        )

        logger.info(f"Completed audit scan with ID: {scan_uuid}")

    except Exception as e:
        logger.exception(f"Error in audit scan {scan_uuid}: {str(e)}")
        await scan_history_service.update_scan_status(scan_uuid, "failed")
        await GlobalStats.increment_scan(status="failed", paid=False, findings=0, lines_of_code=0)
        scan_result = await scan_history_service.get_scan_result(scan_uuid)
        scan_result.summary = "An error occurred during the audit scan."
        scan_result.type = Profiles.NONE
        scan_result.total_findings = 0
        scan_result.findings = []
        await scan_result.save()
    finally:
        logger.info(f"Cleaning up temporary directory: {temp_dir}")
        shutil.rmtree(temp_dir)
