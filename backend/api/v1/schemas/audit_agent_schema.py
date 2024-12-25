from typing import List, Optional
from uuid import UUID

from pydantic import BaseModel, Field

from api.v1.models.repository_docs import QAResponse


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
    docs: Optional[QAResponse] = Field(
        None, description="Optional QA response associated with the request"
    )


class AuditAgentInitiateResponse(BaseModel):
    scan_id: UUID = Field(..., description="Unique identifier for the scan")
