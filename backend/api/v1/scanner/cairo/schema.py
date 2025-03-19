from dataclasses import dataclass
from typing import List, Optional
from uuid import UUID

from pydantic import BaseModel, ConfigDict, Field, field_validator

from core.models.docs import QAResponse
from core.schemas.context_protocols import CompilationContext, GitHubContext, UserContext
from core.schemas.scan_schema import BaseScanContext, ScanType, SetupResult


class CairoRequest(BaseModel):
    """Input request for cairo scan."""

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


@dataclass(kw_only=True)
class CairoScanContext(BaseScanContext):
    """Context for Cairo scans with GitHub and user capabilities."""

    user_email: str
    user_access_token: str
    repository_url: str
    branch_name: str
    scan_type: ScanType = ScanType.CAIRO

    # Optional fields (with defaults)
    user_name: Optional[str] = None
    repository_name: Optional[str] = None
    repo_dir: Optional[str] = None
    temp_dir: Optional[str] = None
    commit_hash: Optional[str] = None
    formatted_docs: Optional[str] = None
    setup_result: Optional[SetupResult] = None

    model_config = ConfigDict(arbitrary_types_allowed=True)
    _supports = (GitHubContext, UserContext, CompilationContext)


class CairoInitiateResponse(BaseModel):
    scan_id: UUID = Field(..., description="Unique identifier for the scan")
