from typing import List, Optional

from pydantic import BaseModel, Field

from common.profiles import Profiles


class Finding(BaseModel):
    Issue: str = Field(..., description="A short description of the vulnerability or issue")
    Severity: str = Field(..., description="Severity level of the issue")
    Contracts: List[str] = Field(..., description="List of affected contract names")
    Description: str = Field(..., description="Detailed description of the issue")
    Recommendation: Optional[str] = Field(None, description="Suggested fix for the issue.")


class ContextScanRequest(BaseModel):
    summary: Optional[str] = Field(None, description="An optional summary of the context")
    contracts: str = Field(..., description="Flattened smart contracts content")
    profile: Profiles = Field(Profiles.NONE, description="Profile to use for the scan")


class ContextScanResponse(BaseModel):
    findings: List[Finding] = Field(..., description="The result of the context scan")
