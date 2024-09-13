from pydantic import BaseModel, Field
from typing import Optional, List
from common.profiles import Profiles  # Import the Profiles enum


class Finding(BaseModel):
    Issue: str = Field(
        ..., description="A short description of the vulnerability or issue"
    )
    Severity: str = Field(..., description="Severity level of the issue")
    Contracts: List[str] = Field(..., description="List of affected contract names")
    Description: str = Field(..., description="Detailed description of the issue")


class ContextScanRequest(BaseModel):
    summary: Optional[str] = Field(
        None, description="An optional summary of the context"
    )
    contracts: str = Field(..., description="Flattened smart contracts content")
    profile: Profiles = Field(
        Profiles.NONE, description="Profile to use for the scan"
    )  # Add profile field


class ContextScanResponse(BaseModel):
    summary: Optional[str] = Field(None, description="The summary provided for context")
    contracts: str = Field(
        ..., description="The smart contracts content that was scanned"
    )
    scan_result: List[Finding] = Field(
        ..., description="The result of the context scan"
    )
