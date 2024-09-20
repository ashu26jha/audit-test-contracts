from uuid import UUID

from api.v1.models.user import User
from api.v1.schemas.audit_agent_schema import ScanResultResponse
from api.v1.services.auth_service import get_current_user
from api.v1.services.scan_history_service import get_scan
from api.v1.services.scan_results_service import (
    get_full_scan_result,
    get_partial_scan_result,
)
from fastapi import APIRouter, Depends, HTTPException, status

router = APIRouter()


@router.get(
    "/scans/{scan_id:uuid}",
    response_model=ScanResultResponse,
)
async def get_audit_agent_result(
    scan_id: UUID,
    current_user: User = Depends(get_current_user),
):
    # Retrieve the scan metadata
    scan = await get_scan(scan_id)
    if scan is None or scan.user_id != str(current_user.id):
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Scan result not found.",
        )
    # Retrieve the full scan result
    scan_result = await get_full_scan_result(scan_id)
    if scan_result is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Scan result not found.",
        )
    return scan_result


@router.get(
    "/scans/partial/{scan_id:uuid}",
    response_model=ScanResultResponse,
)
async def get_partial_audit_agent_result(
    scan_id: UUID,
    current_user: User = Depends(get_current_user),
):
    # Retrieve the scan metadata
    scan = await get_scan(scan_id)
    if scan is None or scan.user_id != str(current_user.id):
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Scan result not found.",
        )
    # Retrieve the partial scan result
    scan_result = await get_partial_scan_result(scan_id)
    if scan_result is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Scan result not found.",
        )
    return scan_result
