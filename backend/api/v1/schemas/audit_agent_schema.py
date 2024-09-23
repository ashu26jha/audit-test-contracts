from datetime import datetime
from typing import Dict, List, Optional
from uuid import UUID

from api.v1.schemas.context_scan_schema import Finding
from common.profiles import Profiles
from pydantic import BaseModel, ConfigDict, Field


class AuditAgentRequest(BaseModel):
    repositoryURL: str = Field(..., description="URL of the GitHub repository to scan")
    contractFiles: List[str] = Field(
        ...,
        description="Array of relative file paths within the repository (e.g., 'contracts/MyContract.sol')",
    )
    branchName: str = Field(
        default="main",
        description="Name of the branch to scan. Defaults to 'main' if not provided.",
    )


class AuditAgentInitiateResponse(BaseModel):
    scan_id: UUID = Field(..., description="Unique identifier for the scan")


class ScanResponse(BaseModel):
    scan_id: UUID
    status: str
    startedAt: datetime
    completedAt: Optional[datetime]
    contractFiles: List[str]
    linesOfCode: Optional[Dict[str, int]] = None
    branchName: str
    commitHash: Optional[str]
    paid_status: bool
    user_id: str = Field(exclude=True)
    createdAt: datetime = Field(exclude=True)
    updatedAt: datetime = Field(exclude=True)

    model_config = ConfigDict(from_attributes=True)


class ScanResultResponse(BaseModel):
    scan_id: UUID
    summary: Optional[str]
    type: Optional[Profiles]
    findings: List[Finding]
    createdAt: datetime
    updatedAt: datetime

    model_config = ConfigDict(
        from_attributes=True,
    )
