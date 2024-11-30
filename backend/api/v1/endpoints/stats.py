from typing import Union

from fastapi import APIRouter, Depends, Response, status

from api.v1.schemas.api_response_schema import ErrorResponse, SuccessResponse
from api.v1.services.auth_service import get_api_key
from api.v1.services.stats_service import get_global_stats

router = APIRouter()


@router.get(
    "/global-stats",
    dependencies=[Depends(get_api_key)],
    response_model=Union[SuccessResponse, ErrorResponse],
)
async def get_stats(response: Response):
    """
    Get global statistics about scans.
    Requires API key authentication.
    """
    try:
        stats = await get_global_stats()
        return SuccessResponse(data=stats)
    except Exception as e:
        response.status_code = status.HTTP_500_INTERNAL_SERVER_ERROR
        return ErrorResponse(
            code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            message="An error occurred while fetching global stats",
            details=str(e),
        )
