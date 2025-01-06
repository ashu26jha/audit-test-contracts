from typing import Union

from fastapi import APIRouter

from api.v1.utilities.summary.schema import SummaryRequest, SummaryResponse
from api.v1.utilities.summary.service import generate_summary
from core.schemas.api_response_schema import ErrorResponse, SuccessResponse

router = APIRouter(tags=["Utilities"])


@router.post(
    "/generate-summary",
    response_model=Union[SuccessResponse[SummaryResponse], ErrorResponse],
    description="Generate a summary of the selected contracts.",
)
async def get_summary(request: SummaryRequest):
    """
    Generate a summary of the selected contracts.

    Args:
        request (SummaryRequest): The request object containing the selected contracts

    Returns:
        SummaryResponse: The summary response containing the summary and contract type
    """
    summary, contract_type = await generate_summary(request.contracts)
    return SuccessResponse(data=SummaryResponse(summary=summary, type=contract_type))
