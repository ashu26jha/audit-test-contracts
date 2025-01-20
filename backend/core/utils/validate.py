import re
from datetime import datetime, timedelta, timezone
from typing import List
from uuid import UUID

from fastapi import HTTPException

from config.subscription_settings import SUBSCRIPTION_SETTINGS
from core.db.repositories.scan import ScanRepository
from core.db.repositories.user import UserRepository
from core.models.scan import Scan
from core.models.user import User
from core.schemas.audit_agent_schema import FreeScanStatus
from core.utils.logger import logger

# Regular expression for GitHub repository URL validation
GITHUB_URL_PATTERN = r"^https?://github\.com/[\w.-]+/[\w.-]+(?:\.git)?$"


async def validate_user_scan_access(scan_id: UUID, current_user: User):
    scan = await ScanRepository.get_scan(scan_id)
    if not scan or scan.user_id != current_user.githubId:
        raise HTTPException(status_code=404, detail=f"Scan with ID {scan_id} not found")
    return scan


async def validate_no_in_progress_scans(user: User):
    """Validate that the user has no in-progress or pending scans."""
    scans = await ScanRepository.get_scan_history(user)
    for scan in scans:
        if scan.status in ["in_progress", "pending"]:
            raise HTTPException(
                status_code=400,
                detail="You have an ongoing scan. Please wait for it to complete before starting a new one.",
            )


def validate_user_has_github_token(user: User):
    """Validate if the user has a GitHub access token on file."""
    if not user.accessToken:
        raise HTTPException(
            status_code=403, detail="User does not have a GitHub access token on file."
        )


def validate_github_url(url: str):
    """Validate if the given URL is a valid GitHub repository URL."""
    if not bool(re.match(GITHUB_URL_PATTERN, url)):
        raise HTTPException(status_code=400, detail="Invalid GitHub repository URL")


def validate_contract_files(contract_files: List[str]):
    """Validate if the given contract files are valid Solidity files."""
    if not contract_files:
        raise HTTPException(status_code=400, detail="No contract files provided")
    if not all(file.endswith(".sol") for file in contract_files):
        raise HTTPException(
            status_code=400,
            detail="Invalid contract files. All files must have a .sol extension",
        )


async def validate_free_scan_limit(user_id: str) -> FreeScanStatus:
    """
    Checks if a user can perform a free scan based on their scan history.
    A user is allowed one free scan per month if they are not a subscriber.

    Args:
        user_id: The GitHub ID of the user

    Returns:
        FreeScanStatus: Object containing whether scan is allowed and when next scan will be available

    Raises:
        HTTPException: If user is not found or other server errors occur
    """
    try:
        # Get user to check subscription status
        user = await UserRepository.get_by_github_id(user_id)
        if not user:
            raise HTTPException(status_code=404, detail="User not found")

        # Check scans in the last 30 days
        thirty_days_ago = datetime.now(timezone.utc) - timedelta(days=30)
        recent_scans = await Scan.find(
            {
                "user_id": user_id,
                "createdAt": {"$gte": thirty_days_ago},
                "paid_status": False,  # Only check non-paid (free) scans
                "status": "completed",  # Only count completed scans
            }
        ).to_list()

        if not recent_scans:
            return FreeScanStatus(is_allowed=True, next_available_at=None)

        # Get the most recent scan's date and calculate next available date
        most_recent_scan = max(recent_scans, key=lambda x: x.createdAt)
        next_available_at = most_recent_scan.createdAt + timedelta(days=30)

        return FreeScanStatus(
            is_allowed=False,
            next_available_at=next_available_at,
        )

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error validating free scan limit for user {user_id}: {str(e)}")
        raise HTTPException(status_code=500, detail="Failed to validate free scan limit") from e


async def validate_subscription_limits(user_id: str, contract_files: List[str], total_loc: int):
    """Validate subscription limits for contracts and LoC."""
    user = await UserRepository.get_by_github_id(user_id)

    plan = user.subscription.type
    limits = SUBSCRIPTION_SETTINGS[plan]

    if len(contract_files) > limits["max_contracts"]:
        raise HTTPException(
            status_code=400, detail=f"Maximum {limits['max_contracts']} contracts allowed"
        )

    # TODO: Check that calculation matches the one in the frontend
    if total_loc > limits["max_loc"]:
        raise HTTPException(
            status_code=400, detail=f"Maximum {limits['max_loc']} lines of code allowed"
        )


def is_valid_eth_address(address: str) -> bool:
    """Validates basic Ethereum address format.

    Only checks if the address:
    1. Starts with '0x'
    2. Is followed by 40 hexadecimal characters
    3. Has total length of 42 characters
    """
    # Check if it's a string and has basic format (0x followed by 40 chars)
    if not isinstance(address, str) or not address.startswith("0x") or len(address) != 42:
        return False

    # Check if all characters after 0x are valid hex
    try:
        int(address[2:], 16)
        return True
    except ValueError:
        return False
