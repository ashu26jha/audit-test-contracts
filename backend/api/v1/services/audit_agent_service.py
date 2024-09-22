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
from common.exceptions import (
    InternalServerError,
    JSONParsingError,
    UnauthorizedError,
    ValidationError,
)
from common.logger import logger
from common.profiles import Profiles
from fastapi import BackgroundTasks

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

        # Flatten contracts and count lines of code
        flattened_contracts = await flatten_contracts_service.flatten_contracts(
            request.repositoryURL, request.contractFiles, user.accessToken
        )
        lines_of_code = await lines_of_code_service.count_lines_of_code(flattened_contracts)

        print(lines_of_code)

        # Create and store the new scan
        new_scan = Scan(
            scan_id=scan_id,
            user_id=str(user.id),
            status="pending",
            startedAt=datetime.now(timezone.utc),
            contractFiles=request.contractFiles,
            linesOfCode=lines_of_code,
        )
        await scan_history_service.store_scan(new_scan)

        # Start the background task
        background_tasks.add_task(
            perform_audit_agent_background,
            scan_id,
            flattened_contracts,
        )

    except (UnauthorizedError, ValidationError) as e:
        await scan_history_service.update_scan_status(scan_id, "failed")
        raise e
    except Exception as e:
        logger.exception(f"Unexpected error during scan initiation: {str(e)}")
        await scan_history_service.update_scan_status(scan_id, "failed")
        raise InternalServerError("Failed to initiate audit scan") from e


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

        # Create the scan result using the Beanie model
        scan_result = ScanResult(
            scan_id=scan_id,
            summary=summary_result,
            type=detected_profile,
            findings=context_scan_result,
        )
        await scan_history_service.store_scan_result(scan_result)

        # Update scan status to 'completed'
        await scan_history_service.update_scan_status(scan_id, "completed")

        logger.info(f"Completed audit scan with ID: {scan_id}")

    except (ValidationError, JSONParsingError) as e:
        logger.exception(f"Validation error in audit scan {scan_id}: {str(e)}")
        await scan_history_service.update_scan_status(scan_id, "failed")
        error_result = ScanResult(
            scan_id=scan_id,
            summary=f"Error occurred during scan: {str(e)}",
            type=Profiles.NONE,
            findings=[],
        )
        await scan_history_service.store_scan_result(error_result)
    except Exception as e:
        logger.exception(f"Unexpected error in audit scan {scan_id}: {str(e)}")
        await scan_history_service.update_scan_status(scan_id, "failed")
        error_result = ScanResult(
            scan_id=scan_id,
            summary="An unexpected error occurred during the audit scan.",
            type=Profiles.NONE,
            findings=[],
        )
        await scan_history_service.store_scan_result(error_result)


def validate_user_has_github_token(user: User) -> bool:
    """Validate if the user has a GitHub access token on file."""
    if not user.accessToken:
        raise UnauthorizedError("User does not have a GitHub access token on file.")


def validate_github_url(url: str) -> bool:
    """Validate if the given URL is a valid GitHub repository URL."""
    if not bool(re.match(GITHUB_URL_PATTERN, url)):
        raise ValidationError("Invalid GitHub repository URL")


def validate_contract_files(contract_files: List[str]) -> bool:
    """Validate if the given contract files are valid Solidity files."""
    if not contract_files:
        raise ValidationError("No contract files provided")
    if not all(file.endswith(".sol") for file in contract_files):
        raise ValidationError("Invalid contract files. All files must have a .sol extension")
