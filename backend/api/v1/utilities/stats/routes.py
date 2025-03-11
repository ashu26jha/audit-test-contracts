from typing import Union

from fastapi import APIRouter, Depends, Response, status

from api.v1.auth.helpers.dependencies import get_api_key
from api.v1.utilities.stats.schema import GlobalStatsResponse, TwentyFourHStatsResponse
from core.schemas.api_response_schema import ErrorResponse, SuccessResponse

from .service import StatsService

router = APIRouter(tags=["stats"])


@router.get(
    "/global-stats",
    dependencies=[Depends(get_api_key)],
    response_model=Union[SuccessResponse[GlobalStatsResponse], ErrorResponse],
)
async def get_global_stats(response: Response):
    """
    Get global statistics about scans.
    Requires API key authentication.
    """
    try:
        stats = await StatsService.get_global_stats()
        return SuccessResponse(data=stats)
    except Exception as e:
        response.status_code = status.HTTP_500_INTERNAL_SERVER_ERROR
        return ErrorResponse(
            code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            message="An error occurred while fetching global stats",
            details=str(e),
        )


@router.get(
    "/24h-stats",
    dependencies=[Depends(get_api_key)],
    response_model=Union[SuccessResponse[TwentyFourHStatsResponse], ErrorResponse],
)
async def get_24h_stats(response: Response):
    """
    Get 24h statistics about scans.
    Requires API key authentication.
    """
    try:
        stats = await StatsService.get_24h_stats()
        return SuccessResponse(data=stats)
    except Exception as e:
        response.status_code = status.HTTP_500_INTERNAL_SERVER_ERROR
        return ErrorResponse(
            code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            message="An error occurred while fetching 24h stats",
            details=str(e),
        )
