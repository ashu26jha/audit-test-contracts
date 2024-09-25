from datetime import datetime
from typing import Dict, List, Optional
from uuid import UUID

from api.v1.schemas.context_scan_schema import Finding
from common.profiles import Profiles
from pydantic import BaseModel, ConfigDict, Field


class ScanResponse(BaseModel):
    scan_id: UUID
    scan_number: int
    status: str
    startedAt: datetime
    completedAt: Optional[datetime]
    contractFiles: List[str]
    linesOfCode: Optional[Dict[str, int]] = None
    repositoryURL: Optional[str] = None
    repositoryName: Optional[str] = None
    branchName: str
    commitHash: Optional[str]
    paid_status: bool
    total_findings: Optional[int] = None
    user_id: str = Field(exclude=True)
    createdAt: datetime = Field(exclude=True)
    updatedAt: datetime = Field(exclude=True)

    model_config = ConfigDict(from_attributes=True)


class ScanResultResponse(BaseModel):
    scan_id: UUID
    scan_number: int
    summary: Optional[str]
    type: Optional[Profiles]
    total_findings: Optional[int] = None
    findings: List[Finding]
    createdAt: datetime
    completedAt: datetime

    model_config = ConfigDict(
        from_attributes=True,
    )
