from uuid import UUID

from api.v1.scans.helpers.scan_result import get_partial_scan_result
from api.v1.scans.schema import (
    FullScanResultResponse,
    PartialScanResultResponse,
    ScanResponse,
    ScanResultResponse,
)
from core.db.repositories.scan import ScanRepository
from core.models.user import User
from core.utils.validate import validate_scan_paid, validate_user_scan_access


class ScanResultService:
    @staticmethod
    async def get_full_result(scan_id: UUID, user: User) -> FullScanResultResponse:
        # Validate user access to scan and paid status
        await validate_user_scan_access(scan_id, user)
        await validate_scan_paid(scan_id)

        scan = await ScanRepository.get_scan(scan_id)
        full_result = await ScanRepository.get_scan_result(scan_id)

        return FullScanResultResponse(
            scan=ScanResponse.model_validate(scan),
            result=ScanResultResponse.model_validate(full_result) if full_result else None,
        )

    @staticmethod
    async def get_partial_result(scan_id: str, user: User) -> PartialScanResultResponse:
        # Validate user access to scan
        await validate_user_scan_access(scan_id, user)

        scan = await ScanRepository.get_scan(scan_id)
        partial_result = await get_partial_scan_result(scan_id)

        return PartialScanResultResponse(
            scan=ScanResponse.model_validate(scan),
            partial_result=(
                ScanResultResponse.model_validate(partial_result) if partial_result else None
            ),
        )


class ScanHistoryService:
    @staticmethod
    async def get_scan_history_for_user(user: User):
        """Retrieve the scan history for a given user."""
        scans = await ScanRepository.get_scan_history(user)
        return scans
