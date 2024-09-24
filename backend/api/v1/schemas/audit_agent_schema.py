from typing import List
from uuid import UUID

from pydantic import BaseModel, Field


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
