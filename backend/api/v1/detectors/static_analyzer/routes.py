from typing import Union

from fastapi import APIRouter, HTTPException, status

from api.v1.detectors.context_scan.schema import FindingList
from api.v1.detectors.static_analyzer.schema import StaticAnalyzerRequest
from api.v1.detectors.static_analyzer.service import run_static_analyzer
from core.schemas.api_response_schema import ErrorResponse, SuccessResponse
from core.utils.errors import DetectorError
from core.utils.logger import logger

router = APIRouter()


@router.post(
    "/static-analyzer",
    response_model=Union[SuccessResponse[FindingList], ErrorResponse],
)
async def static_analyzer(request: StaticAnalyzerRequest):
    """
    Run static analyzers (Slither and Aderyn) on smart contracts.

    Returns:
        The static analysis findings or an error response
    """
    try:
        result = await run_static_analyzer(
            request.github_url, request.oauth_token, request.contracts
        )
        return SuccessResponse(data=result)
    except DetectorError as e:
        logger.error(f"Static analyzer detector failed: {str(e)}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Static analysis failed: {str(e)}",
        )
