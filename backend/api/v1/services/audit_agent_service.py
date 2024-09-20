import re
from typing import List
from uuid import UUID

from api.v1.models.scan import ScanResult
from api.v1.services import (
    context_scan_service,
    flatten_contracts_service,
    generate_summary_service,
    scan_history_service,
)
from common.logger import logger
from common.profiles import Profiles

# Regular expression for GitHub repository URL validation
GITHUB_URL_PATTERN = r"^https?://github\.com/[\w.-]+/[\w.-]+(?:\.git)?$"


def validate_github_url(url: str) -> bool:
    """Validate if the given URL is a valid GitHub repository URL."""
    return bool(re.match(GITHUB_URL_PATTERN, url))


def validate_contract_files(contract_files: List[str]) -> bool:
    """Validate if the given contract files are valid Solidity files."""
    if not contract_files:
        return False
    return all(file.endswith(".sol") for file in contract_files)


async def perform_audit_agent_background(
    scan_id: UUID,
    user_id: str,
    repository_url: str,
    contractFiles: List[str],
    auth_token: str,
):
    try:
        logger.info(f"Starting background audit scan with ID: {scan_id}")

        # Update scan status to 'in_progress'
        await scan_history_service.update_scan_status(scan_id, "in_progress")

        # Step 1: Flatten contracts
        flattened_contracts = await flatten_contracts_service.flatten_contracts(
            repository_url, contractFiles, auth_token
        )

        # Step 2: Generate Summary and detect profile
        summary_result, detected_type = await generate_summary_service.generate_summary(
            flattened_contracts
        )

        # Map 'detected_type' to a Profiles enum member
        try:
            detected_profile = Profiles[detected_type.upper()]
        except KeyError:
            detected_profile = Profiles.DEFAULT

        # Step 3: Perform Context Scan
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

        # Store the scan result
        await scan_result.create()

        # Update scan status to 'completed'
        await scan_history_service.update_scan_status(scan_id, "completed")

        logger.info(f"Completed audit scan with ID: {scan_id}")

    except Exception as e:
        logger.exception(f"Error in background audit scan with ID {scan_id}: {str(e)}")
        # Update scan status to 'failed'
        await scan_history_service.update_scan_status(scan_id, "failed")
        raise
