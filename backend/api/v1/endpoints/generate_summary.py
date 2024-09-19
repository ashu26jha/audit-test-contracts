from api.v1.schemas import generate_summary_schema
from api.v1.services import generate_summary_service
from common.logger import error
from fastapi import APIRouter, HTTPException, status

router = APIRouter()


@router.post("/generate-summary", response_model=generate_summary_schema.SummaryResponse)
async def generate_summary(request: generate_summary_schema.SummaryRequest):
    try:
        summary, contract_type = await generate_summary_service.generate_summary(request.contracts)
        return generate_summary_schema.SummaryResponse(summary=summary, type=contract_type)
    except Exception as e:
        error(f"Error in generate_summary endpoint: {str(e)}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="An error occurred while generating the summary.",
        )
