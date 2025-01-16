from uuid import uuid4

from fastapi import APIRouter, BackgroundTasks, status

from api.v1.agentic.schema import PerAddressAgenticRequest, PerAddressAgenticResponse
from api.v1.agentic.service import AgenticService
from core.schemas.api_response_schema import SuccessResponse

router = APIRouter(prefix="/agentic", tags=["agentic"])


@router.post(
    "/scan-per-address",
    response_model=SuccessResponse,
    status_code=status.HTTP_202_ACCEPTED,
    description="Initiate an agentic scan from a contract address",
)
async def scan_per_address(
    request: PerAddressAgenticRequest,
    background_tasks: BackgroundTasks,
):
    """
    Initiate a full AuditAgent scan from a contract address.

    Args:
        contractAddress (str): The address of the contract to scan
        chainID (int): The chain ID of the contract to scan
        contractFiles (List[str]): The files to scan

    Returns:
        scan_id (UUID): Unique identifier for the scan
    """
    scan_id = uuid4()
    await AgenticService.create_scan_per_address(scan_id, request, background_tasks)
    return SuccessResponse(data=PerAddressAgenticResponse(scan_id=scan_id))
