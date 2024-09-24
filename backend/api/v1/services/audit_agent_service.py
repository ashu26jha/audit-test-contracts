import re
from datetime import datetime, timezone
from typing import List
from uuid import UUID

from api.v1.models.scan import Scan, ScanResult
from api.v1.models.user import User
from api.v1.schemas import audit_agent_schema
from api.v1.services import (
    context_scan_service,
    flatten_contracts_service,
    generate_summary_service,
    lines_of_code_service,
    scan_history_service,
)
from api.v1.services.github_service import GitHubService
from common.logger import logger
from common.profiles import Profiles
from fastapi import BackgroundTasks, HTTPException

github_service = GitHubService()

# Regular expression for GitHub repository URL validation
GITHUB_URL_PATTERN = r"^https?://github\.com/[\w.-]+/[\w.-]+(?:\.git)?$"


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

        # Fetch repository info
        repo_info = await github_service.fetch_github_repo_info(
            user.accessToken, request.repositoryURL
        )

        # Create and store the new scan with initial status 'pending'
        branch_name = request.branchName if request.branchName else "main"
        new_scan = Scan(
            scan_id=scan_id,
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
            summary="Scan in progress",
            type=Profiles.NONE,
            total_findings=0,
            findings=[],
        )
        await scan_history_service.store_scan_result(initial_scan_result)

        # Fetch the commit hash using GitHub API
        commit_hash = await github_service.get_commit_hash(
            user.accessToken, request.repositoryURL, branch_name
        )
        new_scan.commitHash = commit_hash
        await new_scan.save()

        # Flatten contracts and count lines of code
        flattened_contracts = await flatten_contracts_service.flatten_contracts(
            request.repositoryURL, request.contractFiles, user.accessToken
        )
        lines_of_code = await lines_of_code_service.count_lines_of_code(flattened_contracts)
        new_scan.linesOfCode = lines_of_code
        await new_scan.save()

        # Start the background task
        background_tasks.add_task(
            perform_audit_agent_background,
            scan_id,
            flattened_contracts,
        )

    except HTTPException:
        raise
    except Exception as e:
        logger.exception(f"Unexpected error during scan initiation: {str(e)}")
        # Update scan status to 'failed' if scan exists
        try:
            await scan_history_service.update_scan_status(scan_id, "failed")
            # Also update the scan result to reflect the failure
            failed_scan_result = ScanResult(
                scan_id=scan_id,
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
    scan_id: UUID,
    flattened_contracts: str,
):
    try:
        logger.info(f"Starting background audit scan with ID: {scan_id}")

        # Update scan status to 'in_progress'
        await scan_history_service.update_scan_status(scan_id, "in_progress")

        # Generate Summary and detect profile
        summary_result, detected_type = await generate_summary_service.generate_summary(
            flattened_contracts
        )

        detected_profile = (
            Profiles[detected_type.upper()]
            if detected_type.upper() in Profiles.__members__
            else Profiles.DEFAULT
        )

        # Perform Context Scan
        context_scan_result = await context_scan_service.perform_context_scan(
            summary_result, flattened_contracts, detected_profile
        )

        # Calculate total findings
        total_findings = len(context_scan_result)
        logger.info(f"Total findings: {total_findings}")

        # Update the existing scan result
        scan_result = await scan_history_service.get_scan_result(scan_id)
        scan_result.summary = summary_result
        scan_result.type = detected_profile
        scan_result.total_findings = total_findings
        scan_result.findings = context_scan_result
        await scan_result.save()

        # Update scan status to 'completed'
        await scan_history_service.update_scan_status(scan_id, "completed")

        logger.info(f"Completed audit scan with ID: {scan_id}")

    except Exception as e:
        logger.exception(f"Error in audit scan {scan_id}: {str(e)}")
        await scan_history_service.update_scan_status(scan_id, "failed")
        # Update the existing scan result to reflect the failure
        scan_result = await scan_history_service.get_scan_result(scan_id)
        scan_result.summary = "An error occurred during the audit scan."
        scan_result.type = Profiles.NONE
        scan_result.total_findings = 0
        scan_result.findings = []
        await scan_result.save()


def validate_user_has_github_token(user: User) -> bool:
    """Validate if the user has a GitHub access token on file."""
    if not user.accessToken:
        raise HTTPException(
            status_code=401, detail="User does not have a GitHub access token on file."
        )


def validate_github_url(url: str) -> bool:
    """Validate if the given URL is a valid GitHub repository URL."""
    if not bool(re.match(GITHUB_URL_PATTERN, url)):
        raise HTTPException(status_code=400, detail="Invalid GitHub repository URL")


def validate_contract_files(contract_files: List[str]) -> bool:
    """Validate if the given contract files are valid Solidity files."""
    if not contract_files:
        raise HTTPException(status_code=400, detail="No contract files provided")
    if not all(file.endswith(".sol") for file in contract_files):
        raise HTTPException(
            status_code=400,
            detail="Invalid contract files. All files must have a .sol extension",
        )
