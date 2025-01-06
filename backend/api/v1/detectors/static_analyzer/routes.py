from typing import Union

from fastapi import APIRouter

from api.v1.detectors.static_analyzer.schema import StaticAnalyzerRequest, StaticAnalyzerResponse
from api.v1.detectors.static_analyzer.service import run_static_analyzer
from core.schemas.api_response_schema import ErrorResponse, SuccessResponse

router = APIRouter()


@router.post(
    "/static-analyzer",
    response_model=Union[SuccessResponse[StaticAnalyzerResponse], ErrorResponse],
)
async def static_analyzer(request: StaticAnalyzerRequest):
    result = await run_static_analyzer(request.github_url, request.oauth_token, request.contracts)
    return SuccessResponse(data=result)
