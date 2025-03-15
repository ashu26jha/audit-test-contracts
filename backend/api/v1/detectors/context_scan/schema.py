from typing import List, Optional

from pydantic import BaseModel, Field

from core.models.scan import Finding
from core.utils.profiles import Profiles


class FindingList(BaseModel):
    findings: List[Finding]


class ContextScanRequest(BaseModel):
    summary: Optional[str] = Field(None, description="An optional summary of the context")
    docs: Optional[str] = Field(None, description="An optional documentation of the context")
    contracts: str = Field(..., description="Flattened smart contracts content")
    profile: Profiles = Field(Profiles.NONE, description="Profile to use for the scan")


class ContextScanResponse(BaseModel):
    findings: List[Finding] = Field(..., description="The result of the context scan")
