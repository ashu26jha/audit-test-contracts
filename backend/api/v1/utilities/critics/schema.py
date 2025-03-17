from typing import Any, Dict, Generic, List, Optional, TypeVar

from pydantic import BaseModel

from core.models.scan import Finding


class IndexedFinding(BaseModel):
    """
    A model that wraps a Finding with an index for processing through critic steps.
    This standardizes the format across all critic operations.
    """

    index: int
    finding: Finding

    def to_dict(self) -> Dict[str, Any]:
        """
        Convert to a dictionary format suitable for LLM processing.

        This method is specifically designed for preparing findings for LLM consumption
        during the critic phase. It serializes the finding and adds the index field
        to allow the LLM to reference findings by their index in its response.

        Returns:
            Dictionary representation of the indexed finding for LLM processing
        """
        finding_dict = self.finding.model_dump(mode="json")
        finding_dict["index"] = self.index
        return finding_dict


# Generic type for batch processing results
T = TypeVar("T")


class BatchProcessingResult(BaseModel, Generic[T]):
    """
    Generic result model for batch processing operations.
    """

    results: T
    processed_count: int
    original_count: int


class CriticPhaseRequest(BaseModel):
    """Request model for finding critic phase analysis."""

    findings: List[Finding]
    contract_contents: Dict[str, str]


class DeduplicateRequest(BaseModel):
    """Request model for finding deduplication."""

    findings: List[Finding]


class CriticResponse(BaseModel):
    """Response model for critic phase results."""

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


# ------------------------------------------
#  VALIDATION
# ------------------------------------------


class ValidationScore(BaseModel):
    """Validation score for a finding."""

    index: int
    exploitability: int
    impact: int
    detection_confidence: int
    justification: str


class ValidationScoreList(BaseModel):
    """List of validation scores for findings."""

    scores: List[ValidationScore]


class CounterArgument(BaseModel):
    """Counter-argument against a security finding"""

    index: int
    argument_1: str
    argument_2: str


class CounterArgumentsList(BaseModel):
    """List of counter-arguments for findings"""

    counter_arguments: List[CounterArgument]


class ValidationJudgement(BaseModel):
    """Judge's evaluation of a finding based on counter-arguments"""

    index: int
    detection_confidence: int
    justification: str


class ValidationJudgementList(BaseModel):
    """List of validation judgements for findings"""

    judgements: List[ValidationJudgement]
