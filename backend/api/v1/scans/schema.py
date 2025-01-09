from datetime import datetime
from typing import List, Optional
from uuid import UUID

from pydantic import BaseModel, ConfigDict, Field

from core.models.scan import CodeAnalysisResult, Finding
from core.utils.profiles import Profiles


class ScanResponse(BaseModel):
    """Base scan metadata response model."""

    scan_id: UUID
    scan_number: int
    status: str
    startedAt: datetime
    completedAt: Optional[datetime]
    contractFiles: List[str]
    linesOfCode: Optional[CodeAnalysisResult] = None
    repositoryURL: Optional[str] = None
    repositoryName: Optional[str] = None
    branchName: str
    commitHash: Optional[str]
    paid_status: bool
    total_findings: Optional[int] = None
    progress: float = 0.0
    user_id: str = Field(exclude=True)
    createdAt: datetime = Field(exclude=True)
    updatedAt: datetime = Field(exclude=True)

    model_config = ConfigDict(from_attributes=True)


class ScanResultResponse(BaseModel):
    """Base scan result response model."""

    scan_id: UUID
    scan_number: int
    summary: Optional[str]
    info_message: Optional[str] = None
    type: Optional[Profiles]
    total_findings: Optional[int] = None
    findings: List[Finding]
    createdAt: datetime
    completedAt: datetime

    model_config = ConfigDict(from_attributes=True)


class FullScanResultResponse(BaseModel):
    """Full scan result response including both scan metadata and complete results."""

    scan: ScanResponse
    result: Optional[ScanResultResponse]

    model_config = ConfigDict(from_attributes=True)
