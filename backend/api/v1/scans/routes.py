from typing import List, Union
from uuid import UUID

from fastapi import APIRouter, Depends

from api.v1.auth.helpers.dependencies import get_api_key, get_current_user
from api.v1.scans.schema import FullScanResultResponse, PartialScanResultResponse, ScanResponse
from api.v1.scans.service import ScanHistoryService, ScanResultService
from core.models.user import User
from core.schemas.api_response_schema import ErrorResponse, SuccessResponse

router = APIRouter(prefix="/scans", tags=["scans"])


@router.get(
    "/full/{scan_id}",
    dependencies=[Depends(get_api_key)],
    response_model=Union[SuccessResponse[FullScanResultResponse], ErrorResponse],
    description="Get the full scan result for a given scan ID. Requires API key and paid status.",
)
async def get_audit_agent_result(
    scan_id: UUID,
    current_user: User = Depends(get_current_user),
):
    """
    Get the full scan result for a given scan ID.

    Args:
        scan_id (UUID): The ID of the scan to retrieve
        current_user (User): The authenticated user making the request

    Returns:
        FullScanResultResponse: Contains both scan metadata and complete scan results
    """
    result = await ScanResultService.get_full_result(scan_id, current_user)
    return SuccessResponse(data=result)


@router.get(
    "/partial/{scan_id}",
    response_model=Union[SuccessResponse[PartialScanResultResponse], ErrorResponse],
    description="Get the partial scan result for a given scan ID. Available during scan execution.",
)
async def get_partial_audit_agent_result(
    scan_id: UUID,
    current_user: User = Depends(get_current_user),
):
    """
    Get the partial scan result for a given scan ID.

    Args:
        scan_id (UUID): The ID of the scan to retrieve
        current_user (User): The authenticated user making the request

    Returns:
        PartialScanResultResponse: Contains scan metadata and partial results available during execution
    """
    partial_result = await ScanResultService.get_partial_result(scan_id, current_user)
    return SuccessResponse(data=partial_result)


@router.get(
    "/history",
    response_model=Union[SuccessResponse[List[ScanResponse]], ErrorResponse],
    description="Get the scan history for the authenticated user.",
)
async def get_scan_history(current_user: User = Depends(get_current_user)):
    """
    Get the scan history for the authenticated user.

    Args:
        current_user (User): The authenticated user making the request

    Returns:
        List[ScanResponse]: List of all scans associated with the user
    """
    history = await ScanHistoryService.get_scan_history_for_user(current_user)
    return SuccessResponse(data=[ScanResponse.model_validate(scan) for scan in history])
