from fastapi import APIRouter

from api.v1.schemas.api_response_schema import SuccessResponse

router = APIRouter()


@router.get("/health-check", response_model=SuccessResponse)
async def health_check():
    return SuccessResponse(data={"details": "All systems operational"})
