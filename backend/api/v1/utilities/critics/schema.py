from typing import List, Optional

from pydantic import BaseModel

from core.models.scan import Finding


class MitigationRequest(BaseModel):
    """Request model for finding mitigation analysis."""

    findings: List[Finding]
    flattened_contracts: str


class DeduplicateRequest(BaseModel):
    """Request model for finding deduplication."""

    findings: List[Finding]


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


# ------------------------------------------
#  DEDUPLICATION
# ------------------------------------------


class IndexedFindingList(BaseModel):
    """Response model for LLM deduplication that returns indexes."""

    indexes: List[int]


# ------------------------------------------
#  MITIGATION
# ------------------------------------------


class MitigationUpdate(BaseModel):
    """Model for LLM mitigation updates."""

    index: int
    severity: str
    comments: Optional[str] = None
    should_be_removed: bool = False


class MitigationUpdateList(BaseModel):
    """Response model for LLM mitigation that returns updates to findings."""

    updates: List[MitigationUpdate]
