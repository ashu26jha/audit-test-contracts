from datetime import datetime, timezone
from typing import List, Optional
from uuid import UUID

from api.v1.models.scan import Scan, ScanResult
from api.v1.models.user import User


async def store_scan(scan: Scan):
    """Store scan metadata."""
    scan.createdAt = datetime.now(timezone.utc)
    scan.updatedAt = datetime.now(timezone.utc)
    await scan.create()


async def update_scan_status(scan_id: UUID, status: str):
    """Update the status of a scan."""
    scan = await Scan.find_one(Scan.scan_id == scan_id)
    if scan:
        scan.status = status
        scan.updatedAt = datetime.now(timezone.utc)
        if status == "completed":
            scan.completedAt = datetime.now(timezone.utc)
        await scan.save()


async def store_scan_result(scan_result: ScanResult):
    """Store the detailed results of a scan."""
    scan_result.createdAt = datetime.now(timezone.utc)
    scan_result.updatedAt = datetime.now(timezone.utc)
    await scan_result.create()


async def get_scan(scan_id: UUID) -> Optional[Scan]:
    """Retrieve scan metadata by scan ID."""
    return await Scan.find_one(Scan.scan_id == scan_id)


async def get_scan_result(scan_id: UUID) -> Optional[ScanResult]:
    """Retrieve scan results by scan ID."""
    return await ScanResult.find_one(ScanResult.scan_id == scan_id)


async def get_scan_history_for_user(user: User) -> List[Scan]:
    """Retrieve the scan history for a given user."""
    scans = await Scan.find(Scan.user_id == str(user.id)).sort("-createdAt").to_list()
    return scans
