from datetime import datetime, timezone
from uuid import UUID, uuid4

from beanie import Document, Indexed
from pydantic import Field


class GitHubRepo(Document):
    id: UUID = Field(default_factory=uuid4, alias="_id")
    repo_url: str = Indexed(unique=True)
    repo_name: str
    repo_full_name: str
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    updated_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))

    class Settings:
        name = "github_repos"
