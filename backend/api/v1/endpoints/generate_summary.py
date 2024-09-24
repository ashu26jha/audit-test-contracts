from api.v1.schemas.api_response_schema import SuccessResponse
from fastapi import APIRouter, status

from api.v1.schemas import generate_summary_schema
from api.v1.services import generate_summary_service

router = APIRouter()


@router.post("/generate-summary", response_model=SuccessResponse, status_code=status.HTTP_200_OK)
async def generate_summary(request: generate_summary_schema.SummaryRequest):
    summary, contract_type = await generate_summary_service.generate_summary(request.contracts)
    return SuccessResponse(
        data=generate_summary_schema.SummaryResponse(summary=summary, type=contract_type)
    )
