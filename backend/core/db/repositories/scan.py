from datetime import datetime, timezone
from typing import Any, Dict, List, Optional
from uuid import UUID

from beanie.operators import Set

from core.models.scan import CodeAnalysisResult, Scan, ScanResult
from core.models.user import User
from core.utils.errors import DatabaseError, QueryError
from core.utils.logger import logger


class ScanNotFoundError(QueryError):
    """Raised when a scan is not found in the database."""

    pass


class ScanResultNotFoundError(QueryError):
    """Raised when a scan result is not found in the database."""

    pass


class ScanRepository:
    """Repository for managing scan records and results in the database."""

    @staticmethod
    async def get_scan(scan_id: UUID) -> Scan:
        """Retrieve scan metadata by scan ID."""
        try:
            scan = await Scan.find_one({"scan_id": scan_id})
            if not scan:
                raise ScanNotFoundError(
                    message=f"Scan with ID {scan_id} not found", details={"scan_id": str(scan_id)}
                )
            return scan
        except ScanNotFoundError:
            raise
        except Exception as e:
            logger.error(f"Failed to fetch scan: {str(e)}")
            raise QueryError(
                message="Failed to fetch scan", details={"scan_id": str(scan_id), "error": str(e)}
            ) from e

    @staticmethod
    async def get_scan_result(scan_id: UUID) -> ScanResult:
        """Retrieve scan results by scan ID."""
        try:
            result = await ScanResult.find_one(ScanResult.scan_id == scan_id)
            if not result:
                raise ScanResultNotFoundError(
                    message=f"Scan result with ID {scan_id} not found",
                    details={"scan_id": str(scan_id)},
                )
            return result
        except ScanResultNotFoundError:
            raise
        except Exception as e:
            logger.error(f"Failed to fetch scan result: {str(e)}")
            raise QueryError(
                message="Failed to fetch scan result",
                details={"scan_id": str(scan_id), "error": str(e)},
            ) from e

    @staticmethod
    async def get_scan_history(user: User) -> List[Scan]:
        """Retrieve scan history for a given user."""
        try:
            return await Scan.find({"user_id": user.githubId}).sort("-createdAt").to_list()
        except Exception as e:
            logger.error(f"Failed to fetch scan history: {str(e)}")
            raise QueryError(
                message="Failed to fetch scan history",
                details={"user_id": str(user.githubId), "error": str(e)},
            ) from e

    @staticmethod
    async def store_scan(scan: Scan) -> None:
        """Store scan data."""
        try:
            scan.createdAt = datetime.now(timezone.utc)
            scan.updatedAt = datetime.now(timezone.utc)
            await scan.create()
        except Exception as e:
            logger.error(f"Failed to store scan: {str(e)}")
            raise DatabaseError(
                message="Failed to store scan",
                details={"scan_id": str(scan.scan_id), "error": str(e)},
            ) from e

    @staticmethod
    async def store_scan_result(scan_result: ScanResult, is_new: bool = True) -> None:
        """
        Store or update scan results in the database.

        Args:
            scan_result: The ScanResult object to save
            is_new: Whether this is a new result (True) or an update (False)
        """
        try:
            if is_new:
                scan_result.createdAt = datetime.now(timezone.utc)
                scan_result.completedAt = datetime.now(timezone.utc)
                await scan_result.create()
            else:
                scan_result.completedAt = datetime.now(timezone.utc)
                await scan_result.save()
        except Exception as e:
            action = "create" if is_new else "update"
            logger.error(f"Failed to {action} scan result: {str(e)}")
            raise DatabaseError(
                message=f"Failed to {action} scan result",
                details={"scan_id": str(scan_result.scan_id), "is_new": is_new, "error": str(e)},
            ) from e

    @staticmethod
    async def update_scan(scan_id: UUID, **updates: Dict[str, Any]) -> None:
        """
        Generic method to update scan fields.

        Args:
            scan_id: The ID of the scan to update
            **updates: Dictionary of field names and their new values

        Raises:
            ScanNotFoundError: If scan not found
            DatabaseError: If update fails
        """
        try:
            # Always update the updatedAt timestamp
            updates["updatedAt"] = datetime.now(timezone.utc)
            scan = await ScanRepository.get_scan(scan_id)
            await scan.update(Set(updates))
        except ScanNotFoundError:
            raise
        except Exception as e:
            logger.error("Failed to update scan %s: %s", scan_id, str(e))
            raise DatabaseError(
                message="Failed to update scan",
                details={"scan_id": str(scan_id), "updates": updates, "error": str(e)},
            ) from e

    @staticmethod
    async def update_scan_contract_files(scan_id: UUID, contract_files: List[str]) -> None:
        """Update the contract files of a scan."""
        await ScanRepository.update_scan(scan_id, contractFiles=contract_files)

    @staticmethod
    async def update_scan_commit_hash(scan_id: UUID, commit_hash: str) -> None:
        """Update the commit hash of a scan."""
        await ScanRepository.update_scan(scan_id, commitHash=commit_hash)

    @staticmethod
    async def update_scan_lines_of_code(scan_id: UUID, lines_of_code: CodeAnalysisResult) -> None:
        """Update the lines of code of a scan."""
        await ScanRepository.update_scan(scan_id, linesOfCode=lines_of_code)

    @staticmethod
    async def update_scan_repo_name(scan_id: UUID, repo_name: str) -> None:
        """Update the repo name of a scan."""
        await ScanRepository.update_scan(scan_id, repositoryName=repo_name)

    @staticmethod
    async def update_scan_progress(scan_id: UUID, progress: float) -> None:
        """Update the progress of a scan."""
        await ScanRepository.update_scan(scan_id, progress=progress)

    @staticmethod
    async def update_scan_status(
        scan_id: UUID, status: str, total_findings: Optional[int] = None
    ) -> None:
        """Update the status of a scan."""
        updates = {"status": status}

        if status in ["completed", "failed"]:
            updates["completedAt"] = datetime.now(timezone.utc)

        if total_findings is not None:
            updates["total_findings"] = total_findings

        await ScanRepository.update_scan(scan_id, **updates)

    @staticmethod
    async def update_scan_paid_status(
        scan_id: UUID, paid_status: bool, discount_applied: bool = False
    ) -> None:
        """Update the paid status of a scan."""
        updates = {
            "paid_status": paid_status,
            "discount_applied": discount_applied,
        }
        await ScanRepository.update_scan(scan_id, **updates)

    @staticmethod
    async def update_scan_failure(scan_id: UUID, error_message: str) -> None:
        """
        Special method for handling scan failures with specific failure logic.
        Updates both scan and scan_result records.

        This is kept separate due to its specific error handling requirements
        and the need to update multiple records.
        """
        try:
            # Update scan result but keep findings for debugging if any
            scan_result = await ScanRepository.get_scan_result(scan_id)
            if scan_result:
                scan_result.info_message = error_message or "Scan failed"
                scan_result.completedAt = datetime.now(timezone.utc)
                scan_result.total_findings = 0
                await scan_result.save()

            # Update scan status
            scan_updates = {
                "status": "failed",
                "completedAt": datetime.now(timezone.utc),
                "total_findings": 0,
                "info_message": error_message,
            }
            await ScanRepository.update_scan(scan_id, **scan_updates)
        except ScanResultNotFoundError:
            # If no result exists yet, just update the scan
            await ScanRepository.update_scan(scan_id, **scan_updates)
        except Exception as e:
            logger.error("Failed to update scan failure state: %s", str(e))
            raise DatabaseError(
                message="Failed to update scan failure state",
                details={"scan_id": str(scan_id), "error_message": error_message, "error": str(e)},
            ) from e
