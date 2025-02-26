from typing import Union

from fastapi import APIRouter

from api.v1.detectors.context_scan.schema import ContextScanRequest, ContextScanResponse
from api.v1.detectors.context_scan.service import run_context_scan
from core.schemas.api_response_schema import ErrorResponse, SuccessResponse

router = APIRouter()


@router.post(
    "/context-scan",
    response_model=Union[SuccessResponse[ContextScanResponse], ErrorResponse],
    description="Run a context scan on a repository with few-shot learning.",
)
async def context_scan(request: ContextScanRequest):
    """
    Run a context scan on a repository with few-shot learning.

    Args:
        summary (str): An optional summary of the context
        docs (str): An optional documentation of the context
        contracts (str): Flattened smart contracts content
        profile (Profiles): Profile to use for the scan

    Returns:
        findings (List[Finding]): The result of the context scan
    """
    response = await run_context_scan(
        contracts=request.contracts,
        summary=request.summary,
        docs=request.docs,
        invariants=None,
        profile=request.profile,
    )
    return SuccessResponse(data=response)
