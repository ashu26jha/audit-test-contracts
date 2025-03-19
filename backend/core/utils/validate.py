import re
from datetime import datetime, timedelta, timezone
from typing import List
from uuid import UUID

from config.subscription_settings import SUBSCRIPTION_SETTINGS
from core.db.repositories.scan import ScanRepository
from core.db.repositories.user import UserRepository
from core.models.scan import Scan
from core.models.user import User
from core.schemas.scan_schema import FreeScanStatus
from core.utils.errors import (
    AuthError,
    AuthorizationError,
    ContractError,
    DatabaseError,
    RepositoryError,
    ScanError,
    SubscriptionError,
    ValidationError,
)
from core.utils.logger import logger

# Regular expression for GitHub repository URL validation
GITHUB_URL_PATTERN = r"^https?://github\.com/[\w.-]+/[\w.-]+(?:\.git)?$"


async def validate_user_scan_access(scan_id: UUID, current_user: User) -> Scan:
    """
    Validate user's access to a scan.

    Raises:
        AuthorizationError: If user doesn't have access to the scan
        DatabaseError: From repository layer
    """
    scan = await ScanRepository.get_scan(scan_id)
    if not scan or scan.user_id != current_user.githubId:
        raise AuthorizationError(
            message=f"Scan with ID {scan_id} not found or access denied",
            details={"scan_id": str(scan_id), "user_id": current_user.githubId},
        )
    return scan


async def validate_no_in_progress_scans(user: User) -> None:
    """
    Validate that the user has no in-progress or pending scans.

    Raises:
        ScanError: If user has ongoing scans
        DatabaseError: From repository layer
    """
    scans = await ScanRepository.get_scan_history(user)
    for scan in scans:
        if scan.status in ["in_progress", "pending"]:
            raise ScanError(
                message="You have an ongoing scan. Please wait for it to complete before starting a new one.",
                details={
                    "user_id": user.githubId,
                    "scan_id": str(scan.scan_id),
                    "status": scan.status,
                },
            )


def validate_user_has_github_token(user: User) -> None:
    """
    Validate if the user has a GitHub access token on file.

    Raises:
        AuthError: If user doesn't have a GitHub token
    """
    if not user.accessToken:
        raise AuthError(
            message="User does not have a GitHub access token on file",
            details={"user_id": user.githubId},
        )


def validate_github_url(url: str) -> None:
    """
    Validate if the given URL is a valid GitHub repository URL.

    Raises:
        RepositoryError: If the URL is not a valid GitHub repository URL
    """
    if not bool(re.match(GITHUB_URL_PATTERN, url)):
        raise RepositoryError(message="Invalid GitHub repository URL", details={"url": url})


def validate_solidity_files(contract_files: List[str]) -> None:
    """
    Validate if the given contract files are valid Solidity files.

    Raises:
        ContractError: If the contract files are invalid
    """
    if not contract_files:
        raise ContractError(message="No contract files provided", details={"files": contract_files})
    if not all(file.endswith(".sol") for file in contract_files):
        raise ContractError(
            message="Invalid contract files",
            details={"files": contract_files, "reason": "All files must have a .sol extension"},
        )


def validate_cairo_files(contract_files: List[str]) -> None:
    """
    Validate if the given contract files are valid Cairo files.

    Raises:
        ContractError: If the contract files are invalid
    """
    if not contract_files:
        raise ContractError(message="No contract files provided", details={"files": contract_files})
    if not all(file.endswith(".cairo") for file in contract_files):
        raise ContractError(
            message="Invalid contract files",
            details={"files": contract_files, "reason": "All files must have a .cairo extension"},
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
        ValidationError: If user is not found or validation fails
        DatabaseError: If database operations fail
    """
    try:
        # Get user to check subscription status
        user = await UserRepository.get_by_github_id(user_id)
        if not user:
            raise ValidationError(
                message="User not found",
                details={"user_id": user_id, "error_type": "user_not_found"},
            )

        # Check scans in the last 30 days
        thirty_days_ago = datetime.now(timezone.utc) - timedelta(days=30)
        try:
            recent_scans = await Scan.find(
                {
                    "user_id": user_id,
                    "createdAt": {"$gte": thirty_days_ago},
                    "paid_status": False,  # Only check non-paid (free) scans
                    "status": "completed",  # Only count completed scans
                }
            ).to_list()
        except Exception as db_error:
            logger.error(f"Database error while fetching scans for user {user_id}: {str(db_error)}")
            raise DatabaseError(
                message="Failed to fetch recent scans",
                details={
                    "user_id": user_id,
                    "error_type": "scan_fetch_failed",
                    "error": str(db_error),
                },
            ) from db_error

        if not recent_scans:
            return FreeScanStatus(is_allowed=True, next_available_at=None)

        # Get the most recent scan's date and calculate next available date
        most_recent_scan = max(recent_scans, key=lambda x: x.createdAt)
        next_available_at = most_recent_scan.createdAt + timedelta(days=30)

        return FreeScanStatus(
            is_allowed=False,
            next_available_at=next_available_at,
        )

    except (ValidationError, DatabaseError):
        raise
    except Exception as e:
        logger.error(f"Unexpected error validating free scan limit for user {user_id}: {str(e)}")
        raise ValidationError(
            message="Failed to validate free scan limit",
            details={"user_id": user_id, "error_type": "unexpected_error", "error": str(e)},
        ) from e


async def validate_subscription_limits(
    user_id: str, contract_files: List[str], total_loc: int
) -> None:
    """
    Validate subscription limits for contracts and LoC.

    Raises:
        SubscriptionError: If subscription limits are exceeded
        ValidationError: If user is not found
        DatabaseError: From repository layer
    """
    user = await UserRepository.get_by_github_id(user_id)
    if not user:
        raise ValidationError(message="User not found", details={"user_id": user_id})

    plan = user.subscription.type
    limits = SUBSCRIPTION_SETTINGS[plan]

    if len(contract_files) > limits["max_contracts"]:
        raise SubscriptionError(
            message=f"Maximum {limits['max_contracts']} contracts allowed",
            details={
                "user_id": user_id,
                "plan": plan,
                "current_contracts": len(contract_files),
                "max_contracts": limits["max_contracts"],
            },
        )

    # Note: A 2% buffer is added to the max LoC limit to accommodate possible inconsistencies
    if total_loc > limits["max_loc"]:
        raise SubscriptionError(
            message=f"Maximum {limits['max_loc']} lines of code allowed",
            details={
                "user_id": user_id,
                "plan": plan,
                "current_loc": total_loc,
                "max_loc": limits["max_loc"],
            },
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
