from datetime import datetime, timezone
from typing import List, Optional
from uuid import UUID

from fastapi import HTTPException

from core.models.scan import CodeAnalysisResult, Scan, ScanResult
from core.models.user import User
from core.utils.logger import logger


class ScanRepository:
    """Repository for managing scan records and results in the database."""

    @staticmethod
    async def get_scan(scan_id: UUID) -> Scan:
        """Retrieve scan metadata by scan ID."""
        scan = await Scan.find_one({"scan_id": scan_id})
        if not scan:
            raise HTTPException(status_code=404, detail=f"Scan with ID {scan_id} not found")
        return scan

    @staticmethod
    async def get_scan_result(scan_id: UUID) -> ScanResult:
        """Retrieve scan results by scan ID."""
        result = await ScanResult.find_one(ScanResult.scan_id == scan_id)
        if not result:
            raise HTTPException(status_code=404, detail=f"Scan result with ID {scan_id} not found")
        return result

    @staticmethod
    async def get_scan_history(user: User) -> List[Scan]:
        """Retrieve scan history for a given user."""
        return await Scan.find({"user_id": user.githubId}).sort("-createdAt").to_list()

    @staticmethod
    async def store_scan(scan: Scan) -> None:
        """Store scan data."""
        try:
            scan.createdAt = datetime.now(timezone.utc)
            scan.updatedAt = datetime.now(timezone.utc)
            await scan.create()
        except Exception as e:
            logger.error(f"Error storing scan {scan.scan_id}: {str(e)}")
            raise HTTPException(status_code=500, detail="Failed to store scan") from e

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
            logger.error(f"Error storing scan result for scan {scan_result.scan_id}: {str(e)}")
            raise HTTPException(status_code=500, detail="Failed to store scan result") from e

    @staticmethod
    async def update_scan_status(
        scan_id: UUID, status: str, total_findings: Optional[int] = None
    ) -> None:
        """
        Update the status of a scan.

        Args:
            scan_id: UUID of the scan to update
            status: New status value
            total_findings: Optional number of findings
        """
        try:
            scan = await ScanRepository.get_scan(scan_id)
            scan.status = status
            scan.updatedAt = datetime.now(timezone.utc)
            if status in ["completed", "failed"]:
                scan.completedAt = datetime.now(timezone.utc)
            if total_findings is not None:
                scan.total_findings = total_findings
            await scan.save()
        except Exception as e:
            logger.error(f"Error updating scan status for scan {scan_id}: {str(e)}")
            raise HTTPException(status_code=500, detail="Failed to update scan status") from e

    @staticmethod
    async def update_scan_commit_hash(scan_id: UUID, commit_hash: str) -> None:
        """Update the commit hash of a scan."""
        try:
            scan = await ScanRepository.get_scan(scan_id)
            if scan:
                scan.commitHash = commit_hash
                await scan.save()
        except Exception as e:
            logger.error(f"Error updating scan commit hash for scan {scan_id}: {str(e)}")
            raise HTTPException(status_code=500, detail="Failed to update scan commit hash") from e

    @staticmethod
    async def update_scan_lines_of_code(scan_id: UUID, lines_of_code: CodeAnalysisResult) -> None:
        """Update the lines of code of a scan."""
        try:
            scan = await ScanRepository.get_scan(scan_id)
            if scan:
                scan.linesOfCode = lines_of_code
                await scan.save()
        except Exception as e:
            logger.error(f"Error updating scan lines of code for scan {scan_id}: {str(e)}")
            raise HTTPException(
                status_code=500, detail="Failed to update scan lines of code"
            ) from e

    @staticmethod
    async def update_scan_progress(scan_id: UUID, progress: float) -> Optional[Scan]:
        """Update the progress of a scan."""
        try:
            scan = await ScanRepository.get_scan(scan_id)
            if scan:
                scan.progress = progress
                await scan.save()
                return scan
            return None
        except Exception as e:
            logger.error(f"Error updating scan progress for scan {scan_id}: {str(e)}")
            raise HTTPException(status_code=500, detail="Failed to update scan progress") from e

    @staticmethod
    async def update_scan_paid_status(
        scan_id: UUID, paid_status: bool, discount_applied: bool = False
    ) -> None:
        """Update the paid status and discount status of a scan."""
        try:
            scan = await ScanRepository.get_scan(scan_id)
            scan.paid_status = paid_status
            scan.discount_applied = discount_applied
            scan.updatedAt = datetime.now(timezone.utc)
            await scan.save()
        except Exception as e:
            logger.error(f"Error updating paid status for scan {scan_id}: {str(e)}")
            raise HTTPException(status_code=500, detail="Failed to update scan paid status") from e

    @staticmethod
    async def update_scan_failure(
        scan_id: UUID,
        error_message: Optional[str] = None,
    ) -> None:
        """
        Comprehensive function to handle scan failures.

        Args:
            scan_id: (UUID) The ID of the scan that failed
            error_message: (Optional[str]) Specific error message to store
        """
        try:
            # Update scan result but keep findings for debugging if any
            scan_result = await ScanRepository.get_scan_result(scan_id)
            if scan_result:
                scan_result.info_message = error_message or "Scan failed"
                scan_result.completedAt = datetime.now(timezone.utc)
                scan_result.total_findings = 0
                await scan_result.save()

            # Update scan status but preserve detector information
            scan = await ScanRepository.get_scan(scan_id)
            if scan:
                scan.status = "failed"
                scan.total_findings = 0
                scan.updatedAt = datetime.now(timezone.utc)
                scan.completedAt = datetime.now(timezone.utc)
                await scan.save()
        except Exception as e:
            logger.error(f"Failed to update scan failure for scan {scan_id}: {str(e)}")
            raise HTTPException(status_code=500, detail="Failed to update scan failure") from e
