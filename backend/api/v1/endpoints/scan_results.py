from uuid import UUID

from fastapi import APIRouter, Depends

from api.v1.models.user import User
from api.v1.schemas.api_response_schema import SuccessResponse
from api.v1.schemas.scan_schema import ScanResponse, ScanResultResponse
from api.v1.services.auth_service import get_current_user
from api.v1.services.scan_history_service import get_scan
from api.v1.services.scan_results_service import get_full_scan_result, get_partial_scan_result
from common.validate import validate_scan_paid, validate_user_scan_access

router = APIRouter()


@router.get("/full/{scan_id}", response_model=SuccessResponse)
async def get_audit_agent_result(
    scan_id: UUID,
    current_user: User = Depends(get_current_user),
):
    scan = await get_scan(scan_id)

    # Check if the scan belongs to the user
    await validate_user_scan_access(scan_id, current_user)
    # Check if scan has been paid for
    await validate_scan_paid(scan_id)

    full_result = await get_full_scan_result(scan_id)

    result = {
        "scan": ScanResponse.model_validate(scan),
        "result": (ScanResultResponse.model_validate(full_result) if full_result else None),
    }
    return SuccessResponse(data=result)


@router.get("/partial/{scan_id}", response_model=SuccessResponse)
async def get_partial_audit_agent_result(
    scan_id: UUID,
    current_user: User = Depends(get_current_user),
):
    scan = await get_scan(scan_id)

    # Check if the scan belongs to the user
    await validate_user_scan_access(scan_id, current_user)

    partial_result = await get_partial_scan_result(scan_id)

    # Combine partial result with scan response
    result = {
        "scan": ScanResponse.model_validate(scan),
        "partial_result": (
            ScanResultResponse.model_validate(partial_result) if partial_result else None
        ),
    }
    return SuccessResponse(data=result)
