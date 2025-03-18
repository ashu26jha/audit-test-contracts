from uuid import UUID

from api.v1.scans.schema import FullScanResultResponse, ScanResponse, ScanResultResponse
from core.db.repositories.scan import ScanRepository
from core.models.user import User
from core.utils.validate import validate_user_scan_access


class ScanResultService:
    @staticmethod
    async def get_full_result(scan_id: UUID, user: User) -> FullScanResultResponse:
        # Validate user access to scan and paid status
        await validate_user_scan_access(scan_id, user)

        scan = await ScanRepository.get_scan(scan_id)
        full_result = await ScanRepository.get_scan_result(scan_id)

        if not user.subscription.isActive:
            full_result.invariants = None

        return FullScanResultResponse(
            scan=ScanResponse.model_validate(scan),
            result=ScanResultResponse.model_validate(full_result) if full_result else None,
        )


class ScanHistoryService:
    @staticmethod
    async def get_scan_history_for_user(user: User):
        """Retrieve the scan history for a given user."""
        scans = await ScanRepository.get_scan_history(user)
        return scans
