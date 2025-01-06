from typing import Union

from fastapi import APIRouter

from api.v1.detectors.fuzzer.schema import FuzzerRequest, FuzzerResponse
from api.v1.detectors.fuzzer.service import FuzzerService
from core.schemas.api_response_schema import ErrorResponse, SuccessResponse

router = APIRouter()


@router.post(
    "/fuzzer",
    response_model=Union[SuccessResponse[FuzzerResponse], ErrorResponse],
    description="Run a fuzzer on a repository",
)
async def execute_fuzzer(request: FuzzerRequest):
    """Run a fuzzer on a repository."""
    result = await FuzzerService.run_fuzzer(
        request.github_url,
        request.oauth_token,
        request.selected_contracts,
        request.setup_result,
    )
    return SuccessResponse(data=result)
