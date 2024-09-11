from fastapi import APIRouter, Depends
from services import generate_summary_service
from api.v1.schemas import generate_summary_schema

router = APIRouter()

@router.post("/generate-summary", response_model=generate_summary_schema.SummaryResponse)
async def generate_summary(request: generate_summary_schema.SummaryRequest):
    return await generate_summary_service.generate_summary(request.text)