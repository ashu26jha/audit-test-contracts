from api.v1.schemas import generate_summary_schema
from api.v1.services import generate_summary_service
from fastapi import APIRouter

router = APIRouter()


@router.post("/generate-summary", response_model=generate_summary_schema.SummaryResponse)
async def generate_summary(request: generate_summary_schema.SummaryRequest):
    summary, contract_type = await generate_summary_service.generate_summary(request.contracts)
    return generate_summary_schema.SummaryResponse(summary=summary, type=contract_type)
