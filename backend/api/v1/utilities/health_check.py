from fastapi import APIRouter

from core.schemas.api_response_schema import SuccessResponse

router = APIRouter(tags=["health"])


@router.get("/health-check", response_model=SuccessResponse)
async def health_check():
    """Check if the API is operational."""
    return SuccessResponse(data={"details": "All systems operational"})
