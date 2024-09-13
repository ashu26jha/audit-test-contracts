from pydantic import BaseModel, Field
from typing import Optional, List
from api.v1.schemas.context_scan_schema import Finding
from common.profiles import Profiles


class AuditAgentRequest(BaseModel):
    contracts: str = Field(..., description="Flattened smart contracts content")
    profile: Profiles = Field(Profiles.NONE, description="Profile to use for the scan")


class AuditAgentResponse(BaseModel):
    summary: Optional[str] = Field(
        None, description="Generated summary of the contracts"
    )
    scan_result: List[Finding] = Field(
        ..., description="The result of the context scan"
    )
