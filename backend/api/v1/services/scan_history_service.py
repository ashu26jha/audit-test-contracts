from datetime import datetime, timezone
from typing import List, Optional
from uuid import UUID

from api.v1.models.global_stats import GlobalStats
from api.v1.models.scan import Scan, ScanResult
from api.v1.models.user import User
from fastapi import HTTPException


async def store_scan(scan: Scan):
    """Store scan metadata."""
    scan.createdAt = datetime.now(timezone.utc)
    scan.updatedAt = datetime.now(timezone.utc)
    await scan.create()


async def update_scan_status(scan_id: UUID, status: str, total_findings: Optional[int] = None):
    """Update the status of a scan."""
    scan = await Scan.find_one(Scan.scan_id == scan_id)
    if scan:
        old_status = scan.status
        scan.status = status
        scan.updatedAt = datetime.now(timezone.utc)
        if status in ["completed", "failed"]:
            scan.completedAt = datetime.now(timezone.utc)
        if total_findings is not None:
            scan.total_findings = total_findings
        await scan.save()

        # Update global stats
        await GlobalStats.update_paid_status(old_status, status)
    else:
        raise HTTPException(status_code=404, detail=f"Scan with ID {scan_id} not found")


async def update_scan_paid_status(scan_uuid: UUID, paid_status: bool):
    """Update the paid status of a scan."""
    scan = await Scan.find_one(Scan.uuid == scan_uuid)
    if scan:
        old_status = "paid" if scan.paid_status else "unpaid"
        scan.paid_status = paid_status
        new_status = "paid" if paid_status else "unpaid"
        scan.updatedAt = datetime.now(timezone.utc)
        await scan.save()

        # Update global stats
        await GlobalStats.update_paid_status(old_status, new_status)
    else:
        raise HTTPException(status_code=404, detail=f"Scan with ID {scan_uuid} not found")


async def store_scan_result(scan_result: ScanResult):
    """Store the detailed results of a scan."""
    scan_result.createdAt = datetime.now(timezone.utc)
    scan_result.completedAt = datetime.now(timezone.utc)
    await scan_result.create()


async def get_scan(scan_id: UUID) -> Scan:
    """Retrieve scan metadata by scan ID."""
    scan = await Scan.find_one(Scan.scan_id == scan_id)
    if not scan:
        raise HTTPException(status_code=404, detail=f"Scan with ID {scan_id} not found")
    return scan


async def get_scan_result(scan_id: UUID) -> ScanResult:
    """Retrieve scan results by scan ID."""
    result = await ScanResult.find_one(ScanResult.scan_id == scan_id)
    if not result:
        raise HTTPException(status_code=404, detail=f"Scan result with ID {scan_id} not found")
    return result


async def get_scan_history_for_user(user: User) -> List[Scan]:
    """Retrieve the scan history for a given user."""
    scans = await Scan.find(Scan.user_id == str(user.id)).sort("-createdAt").to_list()
    return scans
