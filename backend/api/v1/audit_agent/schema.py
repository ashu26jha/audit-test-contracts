from typing import List, Optional
from uuid import UUID

from pydantic import BaseModel, Field, field_validator

from core.models.docs import QAResponse


class AuditAgentRequest(BaseModel):
    """Input request for audit agent scan."""

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

    @field_validator("repositoryURL")
    @classmethod
    def validate_repo_url(cls, v: str) -> str:
        if not v.startswith(("https://github.com/", "git@github.com:")):
            raise ValueError("Invalid GitHub repository URL")
        return v


class ScanContext(BaseModel):
    """Context maintaining the state throughout the scan process."""

    # Core identifiers
    scan_id: UUID
    user_id: str
    user_email: str
    user_access_token: str
    scan_number: int

    # Scan configuration
    repository_url: str
    branch_name: str
    contract_files: List[str]
    is_subscription_scan: bool = False
    formatted_docs: Optional[str] = None

    class Config:
        arbitrary_types_allowed = True


class AuditAgentInitiateResponse(BaseModel):
    scan_id: UUID = Field(..., description="Unique identifier for the scan")


class IsFreeScanAllowedResponse(BaseModel):
    is_allowed: bool
    message: str
