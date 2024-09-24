from uuid import UUID

from pydantic import BaseModel, ConfigDict, Field


class GitHubRepoBase(BaseModel):
    repo_url: str
    repo_name: str
    repo_full_name: str


class GitHubRepoCreate(GitHubRepoBase):
    pass


class GitHubRepoResponse(GitHubRepoBase):
    id: UUID = Field(exclude=True)

    model_config = ConfigDict(from_attributes=True)
