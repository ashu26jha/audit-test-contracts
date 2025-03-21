from uuid import UUID

from api.v1.scans.schema import FullScanResultResponse, ScanResponse, ScanResultResponse
from core.db.repositories.scan import ScanRepository, ScanResultNotFoundError
from core.models.user import User
from core.utils.errors import ScanError
from core.utils.validate import validate_user_scan_access


class ScanResultService:
    @staticmethod
    async def get_full_result(scan_id: UUID, user: User) -> FullScanResultResponse:
        """
        Get the full scan result for a scan.

        Args:
            scan_id: The ID of the scan
            user: The user requesting the scan

        Returns:
            FullScanResultResponse: The scan and its result

        Raises:
            AuthorizationError: If user doesn't have access to the scan
            QueryError: If there's an error querying scan data
            ScanError: If there's an issue with the scan result
        """
        # Validate user access to scan - raise AuthorizationError if needed
        scan = await validate_user_scan_access(scan_id, user)

        try:
            full_result = await ScanRepository.get_scan_result(scan_id)
        except ScanResultNotFoundError:
            raise ScanError(
                message=f"No results found for scan {scan_id}", details={"scan_id": str(scan_id)}
            )

        # Free users don't get access to invariants
        if not user.subscription.isActive:
            full_result.invariants = None

        return FullScanResultResponse(
            scan=ScanResponse.model_validate(scan),
            result=ScanResultResponse.model_validate(full_result),
        )


class ScanHistoryService:
    @staticmethod
    async def get_scan_history_for_user(user: User):
        """
        Retrieve the scan history for a given user.

        Args:
            user: The user to get scan history for

        Returns:
            List of scans for the user

        Raises:
            QueryError: If there's an error querying scan history
        """
        # Let repository errors propagate naturally to the route
        return await ScanRepository.get_scan_history(user)
