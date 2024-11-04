from typing import List, Optional

from pydantic import BaseModel, Field, field_validator

from common.profiles import Profiles
from common.severity import Severity  # Import centralized Severity


class Finding(BaseModel):
    Issue: str = Field(..., description="A short description of the vulnerability or issue")
    Severity: str = Field(..., description="Severity level of the issue")
    Contracts: List[str] = Field(..., description="List of affected contract names")
    Description: str = Field(..., description="Detailed description of the issue")
    Recommendation: Optional[str] = Field(None, description="Suggested fix for the issue.")

    @field_validator("Severity")
    def validate_severity(cls, v: str) -> str:
        # Use the centralized Severity enum
        return Severity.from_str(v).value


class FindingList(BaseModel):
    findings: List[Finding]


class ContextScanRequest(BaseModel):
    summary: Optional[str] = Field(None, description="An optional summary of the context")
    contracts: str = Field(..., description="Flattened smart contracts content")
    profile: Profiles = Field(Profiles.NONE, description="Profile to use for the scan")


class ContextScanResponse(BaseModel):
    findings: List[Finding] = Field(..., description="The result of the context scan")
