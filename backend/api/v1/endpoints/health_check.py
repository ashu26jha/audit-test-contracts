from api.v1.schemas.api_response_schema import SuccessResponse
from api.v1.services.auth_service import get_api_key
from fastapi import APIRouter, Depends

router = APIRouter()


@router.get("/health-check", response_model=SuccessResponse)
async def health_check():
    return SuccessResponse(data={"details": "All systems operational"})
