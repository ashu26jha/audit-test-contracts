from typing import Union
from uuid import uuid4

from fastapi import APIRouter, Depends, status

from api.v1.auth.helpers.dependencies import get_api_key, get_current_user
from api.v1.scanner.cairo.schema import (
    CairoInitiateResponse,
    CairoRequest,
)
from api.v1.scanner.cairo.service import CairoService
from core.models.user import User
from core.schemas.api_response_schema import ErrorResponse, SuccessResponse
from core.schemas.scan_schema import ScanType

router = APIRouter(prefix="/cairo", tags=["scanner"])


@router.post(
    "/launch",
    dependencies=[Depends(get_api_key)],
    response_model=Union[SuccessResponse[CairoInitiateResponse], ErrorResponse],
    status_code=status.HTTP_202_ACCEPTED,
    description="Initiate a full Cairo scan",
)
async def perform_cairo(
    request: CairoRequest,
    current_user: User = Depends(get_current_user),
):
    """
    Initiate a full Cairo scan.

    Args:
        repository_url (str): URL of the GitHub repository to scan
        contract_files (List[str]): Array of relative file paths within the repository (e.g., 'contracts/MyContract.sol')
        branch_name (str): Name of the branch to scan. Defaults to 'main' if not provided.
        docs (QAResponse): Optional QA response associated with the request

    Returns:
        SuccessResponse[CairoInitiateResponse]: Response containing:
            - scan_id (UUID): Unique identifier for tracking the scan
    """
    scan_id = uuid4()
    service = CairoService()
    await service.create_scan(scan_id, scan_type=ScanType.CAIRO, user=current_user, request=request)
    return SuccessResponse(data=CairoInitiateResponse(scan_id=scan_id))
