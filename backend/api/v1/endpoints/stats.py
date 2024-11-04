from fastapi import APIRouter, Depends

from api.v1.schemas.api_response_schema import SuccessResponse
from api.v1.services.auth_service import get_api_key
from api.v1.services.stats_service import get_global_stats

router = APIRouter()


@router.get("/global-stats", dependencies=[Depends(get_api_key)], response_model=SuccessResponse)
async def get_stats():
    """
    Get global statistics about scans.
    Requires API key authentication.
    """
    stats = await get_global_stats()
    return SuccessResponse(data=stats)
