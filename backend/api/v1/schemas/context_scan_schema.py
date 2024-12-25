from typing import List, Optional, Union

from pydantic import BaseModel, Field, field_validator

from common.profiles import Profiles
from common.severity import Severity


class Finding(BaseModel):
    Issue: str = Field(..., description="A short description of the vulnerability or issue")
    Severity: str = Field(..., description="Severity level of the issue")
    Contracts: List[str] = Field(..., description="List of affected contract names")
    Description: str = Field(..., description="Detailed description of the issue")
    Recommendation: Optional[str] = Field(None, description="Suggested fix for the issue.")
    Confidence: Optional[Union[int, str]] = Field(None, description="Confidence score of the issue")

    @field_validator("Severity")
    def validate_severity(cls, v: str) -> str:
        # Use the centralized Severity enum
        return Severity.from_str(v).value

    # Compatibility with old databases
    @field_validator("Confidence")
    def validate_confidence(cls, v: Optional[Union[int, str]]) -> Optional[int]:
        if v is None:
            return None
        if isinstance(v, int):
            return v
        if isinstance(v, str):
            severity_map = {"high": 90, "medium": 60, "low": 30, "info": 10}
            if v.lower() in severity_map:
                return severity_map[v.lower()]
            # Integer conversion
            try:
                return int(v)
            except ValueError:
                return None

    class Config:
        # Allow population by field name for backward compatibility
        populate_by_name = True


class FindingList(BaseModel):
    findings: List[Finding]


class InterestingFindings(BaseModel):
    interesting_findings: List[int]


class ContextScanRequest(BaseModel):
    summary: Optional[str] = Field(None, description="An optional summary of the context")
    docs: Optional[str] = Field(None, description="An optional documentation of the context")
    contracts: str = Field(..., description="Flattened smart contracts content")
    profile: Profiles = Field(Profiles.NONE, description="Profile to use for the scan")


class ContextScanResponse(BaseModel):
    findings: List[Finding] = Field(..., description="The result of the context scan")


class MitigationRequest(BaseModel):
    findings: List[Finding]
    flattened_contracts: str
