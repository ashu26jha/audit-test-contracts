from typing import Union

from fastapi import APIRouter, HTTPException, status

from api.v1.detectors.context_scan.schema import ContextScanRequest, ContextScanResponse
from api.v1.detectors.context_scan.service import run_context_scan
from core.schemas.api_response_schema import ErrorResponse, SuccessResponse
from core.utils.errors import DetectorError
from core.utils.logger import logger

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
    try:
        response = await run_context_scan(
            contracts=request.contracts,
            summary=request.summary,
            docs=request.docs,
            invariants=None,
            profile=request.profile,
        )
        return SuccessResponse(data=response)
    except DetectorError as e:
        logger.error(f"Context scan detector failed: {str(e)}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Context scan failed: {str(e)}",
        )
