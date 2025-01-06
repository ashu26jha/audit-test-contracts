from typing import List

from pydantic import BaseModel

from core.models.scan import Finding


class MitigationRequest(BaseModel):
    """Request model for finding mitigation analysis."""

    findings: List[Finding]
    flattened_contracts: str


class DeduplicateRequest(BaseModel):
    """Request model for finding deduplication."""

    findings: List[Finding]


class ConfidenceScoringRequest(BaseModel):
    """Request model for confidence scoring."""

    findings: List[Finding]
    summary_of_project: str
    flattened_contracts: str


class DeduplicateResponse(BaseModel):
    """Response model for deduplication results."""

    original_count: int
    findings_count: int
    findings: List[Finding]


class MitigationResponse(BaseModel):
    """Response model for mitigation analysis results."""

    original_count: int
    findings_count: int
    findings: List[Finding]


class ConfidenceScoringResponse(BaseModel):
    """Response model for confidence scoring results."""

    findings: List[Finding]
