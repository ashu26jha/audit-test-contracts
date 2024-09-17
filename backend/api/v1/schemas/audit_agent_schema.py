from __future__ import annotations

from typing import List, Optional
from uuid import UUID

from api.v1.schemas.context_scan_schema import Finding
from common.profiles import Profiles
from pydantic import BaseModel, Field


class AuditAgentRequest(BaseModel):
    repositoryURL: str = Field(..., description="URL of the GitHub repository to scan")
    contractFiles: List[str] = Field(
        ...,
        description="Array of relative file paths within the repository (e.g., 'contracts/MyContract.sol')",
    )
    authToken: Optional[str] = Field(
        None, description="Authentication token for private repositories (optional)"
    )


class AuditAgentInitiateResponse(BaseModel):
    scan_id: UUID = Field(..., description="Unique identifier for the scan")


class AuditAgentResponse(BaseModel):
    scan_id: UUID = Field(..., description="Unique identifier for the scan")
    summary: Optional[str] = Field(None, description="Generated summary of the contracts")
    type: Optional[Profiles] = Field(
        None, description="Type of the contracts, based on the detected profile"
    )
    scan_result: List[Finding] = Field(
        default_factory=list, description="The result of the context scan"
    )
