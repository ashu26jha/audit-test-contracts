from fastapi import APIRouter

from api.v1.schemas.api_response_schema import SuccessResponse
from common.throttling import throttle

router = APIRouter()


@router.get("/health-check", response_model=SuccessResponse)
@throttle(rate_limit_minutes=5 / 60)
async def health_check():
    return SuccessResponse(data={"details": "All systems operational"})
