from typing import Union
from uuid import uuid4

from fastapi import APIRouter, Depends, status

from api.v1.agentic.schema import PerAddressAgenticRequest, PerAddressAgenticResponse
from api.v1.agentic.service import AgenticService
from api.v1.auth.helpers.dependencies import get_agentic_api_key
from core.schemas.api_response_schema import ErrorResponse, SuccessResponse

router = APIRouter(prefix="/agentic", tags=["agentic"])


@router.post(
    "/scan-per-address",
    dependencies=[Depends(get_agentic_api_key)],
    response_model=Union[SuccessResponse[PerAddressAgenticResponse], ErrorResponse],
    status_code=status.HTTP_202_ACCEPTED,
    description="Initiate an agentic scan from a contract address",
)
async def scan_per_address(request: PerAddressAgenticRequest):
    """
    Initiate an agentic scan for a smart contract address.

    This endpoint initiates a comprehensive security analysis of a smart contract
    using the agentic scanning system. The scan includes:
    - Source code validation and flattening
    - Multiple context-aware security analyses
    - Summary generation and findings deduplication

    Args:
        request (PerAddressAgenticRequest): The request object containing:
            - contractAddress (str): The address of the contract to scan
            - chainId (int): The chain ID where the contract is deployed
            - userEmail (str): Email for notifications and PDF report
            - userName (str): Twitter handle of the user

    Returns:
        SuccessResponse[PerAddressAgenticResponse]: Response containing:
            - scan_id (UUID): Unique identifier for tracking the scan
    """
    scan_id = uuid4()
    await AgenticService.create_scan_per_address(scan_id, request)
    return SuccessResponse(data=PerAddressAgenticResponse(scan_id=scan_id))
