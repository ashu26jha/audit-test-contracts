from uuid import UUID

from api.v1.models.user import User
from api.v1.schemas.api_response_schema import SuccessResponse
from api.v1.services.auth_service import get_current_user
from api.v1.services.scan_history_service import get_scan
from api.v1.services.scan_results_service import (
    get_full_scan_result,
    get_partial_scan_result,
)
from common.exceptions import UnauthorizedError
from fastapi import APIRouter, Depends

router = APIRouter()


@router.get("/scans/{scan_id:uuid}", response_model=SuccessResponse)
async def get_audit_agent_result(
    scan_id: UUID,
    current_user: User = Depends(get_current_user),
):
    scan = await get_scan(scan_id)
    if scan.user_id != str(current_user.id):
        raise UnauthorizedError("User not authorized to access this scan")
    result = await get_full_scan_result(scan_id)
    return SuccessResponse(data=result)


@router.get("/scans/partial/{scan_id:uuid}", response_model=SuccessResponse)
async def get_partial_audit_agent_result(
    scan_id: UUID,
    current_user: User = Depends(get_current_user),
):
    scan = await get_scan(scan_id)
    if scan.user_id != str(current_user.id):
        raise UnauthorizedError("User not authorized to access this scan")
    result = await get_partial_scan_result(scan_id)
    return SuccessResponse(data=result)
