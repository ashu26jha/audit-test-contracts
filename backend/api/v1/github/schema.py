from enum import Enum
from typing import Generic, List, Optional, TypeVar

from pydantic import BaseModel, Field, field_validator

from core.models.docs import QAResponse

T = TypeVar("T")


class FileType(str, Enum):
    """Valid file types for repository contents"""

    SOLIDITY = "sol"
    CAIRO = "cairo"
    README = "readme"


class GitHubErrorDetail(BaseModel):
    """Detailed error information from GitHub API"""

    resource: Optional[str] = None
    field: Optional[str] = None
    code: str
    message: str


class GitHubErrorResponse(BaseModel):
    """Standardized error response"""

    status: int
    message: str
    details: Optional[List[GitHubErrorDetail]] = None


class GitHubPaginatedResponse(BaseModel, Generic[T]):
    """Generic paginated response"""

    items: List[T]
    total_count: int = Field(..., description="Total number of items available")
    page: int = Field(..., description="Current page number")
    per_page: int = Field(..., description="Number of items per page")
    has_next: bool = Field(..., description="Whether there are more pages")


# Update existing response models with better documentation
class GitHubOrganizationResponse(BaseModel):
    """Organization or user information"""

    login: str = Field(..., description="Username or organization name")
    type: str = Field(..., description="Type of account (user/organization)")
    avatar_url: Optional[str] = Field(None, description="URL to the avatar image")
    url: Optional[str] = Field(None, description="API URL for this resource")
    hasGithubApp: bool = Field(
        ..., description="Indicates if the GitHub App is installed for this organization"
    )


class GitHubRepository(BaseModel):
    """Repository information"""

    name: str = Field(..., description="Repository name")
    updatedAt: str = Field(..., description="Last update timestamp")
    private: bool = Field(..., description="Whether the repository is private")
    owner: str = Field(..., description="Repository owner")
    all_repos_access: bool = Field(..., description="Whether user has access to all repos")
    description: Optional[str] = Field(None, description="Repository description")


class GitHubBranch(BaseModel):
    """Branch information from a GitHub repository"""

    name: str = Field(..., description="Name of the branch")
    isDefault: bool = Field(..., description="Whether this is the default branch of the repository")


class GitHubFileContent(BaseModel):
    """File content information from a GitHub repository"""

    name: str = Field(..., description="Name of the file")
    path: str = Field(..., description="Full path to the file in the repository")
    type: str = Field(..., description="Type of the item (usually 'file')")
    download_url: str = Field(..., description="Raw content download URL")
    token: int = Field(..., description="Number of tokens in the file content")
    lineCount: Optional[int] = Field(
        None, description="Total number of lines in the file (for Solidity and Cairo files)"
    )
    character_count: Optional[int] = Field(
        None, description="Total number of characters (for README files)"
    )
    non_whitespace_character_count: Optional[int] = Field(
        None, description="Number of non-whitespace characters (for README files)"
    )

    @field_validator("path")
    @classmethod
    def validate_file_type(cls, v):
        """Validate file has correct extension based on endpoint usage"""
        if v.lower().endswith(".md") or v.lower().endswith(".sol") or v.lower().endswith(".cairo"):
            return v
        raise ValueError("File must be a Solidity (.sol), Cairo (.cairo), or README (.md) file")


class GitHubRepoInfo(BaseModel):
    repo_name: str
    repo_full_name: str
    owner: str
    default_branch: str
    repo_url: str


class GitHubRepositoryDocs(BaseModel):
    docs: QAResponse
    repository_url: str


class GitHubRepositoryValidation(BaseModel):
    accessible: bool


class GitHubAuthResponse(BaseModel):
    access_token: str
    token_type: str = "bearer"
    user: dict


class GitHubRepositoryListResponse(BaseModel):
    repositories: List[GitHubRepository]
    total: int
    page: int
    limit: int


class GitHubRepositoryResponse(BaseModel):
    repository: GitHubRepository
