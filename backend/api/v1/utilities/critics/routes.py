from typing import Union

from fastapi import APIRouter

from api.v1.utilities.critics.schema import (
    DeduplicateRequest,
    DeduplicateResponse,
    MitigationRequest,
    MitigationResponse,
)
from api.v1.utilities.critics.service import CriticService
from core.schemas.api_response_schema import ErrorResponse, SuccessResponse

router = APIRouter()


@router.post(
    "/remove-duplicates",
    response_model=Union[SuccessResponse[DeduplicateResponse], ErrorResponse],
    description="Remove duplicates from a list of security findings.",
)
async def remove_duplicates(request: DeduplicateRequest):
    """
    Remove duplicates from a list of security findings. If any step fails, returns original findings.

    Uses LLM to analyze findings and identify duplicates based on:
    - Similar vulnerability types
    - Overlapping code locations
    - Related security concerns

    Args:
        findings: List of findings to analyze

    Returns:
        DeduplicateResponse containing:
        - original_count: Number of findings before deduplication
        - findings_count: Number of findings after deduplication
        - findings: List of unique findings
    """
    dedups_findings = await CriticService.remove_duplicates(
        findings=request.findings,
    )

    return SuccessResponse(
        data=DeduplicateResponse(
            original_count=len(request.findings),
            findings_count=len(dedups_findings),
            findings=dedups_findings,
        )
    )


@router.post(
    "/mitigate-findings",
    response_model=Union[SuccessResponse[MitigationResponse], ErrorResponse],
    description="Analyze and potentially adjust finding severities based on specific criteria.",
)
async def test_mitigation(request: MitigationRequest):
    """
    Analyze and potentially adjust finding severities based on specific criteria.

    Examines findings for potential severity adjustments based on:
    - Existing security measures
    - Code context and implementation
    - Common mitigation patterns

    Focuses on:
    - Overflow/underflow checks
    - Reentrancy guards
    - Access control implementations

    Args:
        findings: List of findings to analyze
        flattened_contracts: Contract code for context

    Returns:
        MitigationResponse containing:
        - original_count: Number of findings before mitigation
        - findings_count: Number of findings after mitigation
        - findings: List of findings with adjusted severities
    """
    mitigated_findings = await CriticService.mitigate_findings(
        findings=request.findings,
        flattened_contracts=request.flattened_contracts,
    )

    return SuccessResponse(
        data=MitigationResponse(
            original_count=len(request.findings),
            findings_count=len(mitigated_findings),
            findings=mitigated_findings,
        )
    )
