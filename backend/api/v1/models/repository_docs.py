from datetime import datetime, timezone
from typing import Dict, List, Optional

from beanie import Document
from pydantic import BaseModel, Field


class QAResponse(BaseModel):
    readme: List[str] = Field(
        ...,
        description="Array of relative file paths within the repository (e.g., '/readme.md')",
    )
    qa: Dict[str, str]  # Mapping string keys to string values


class RepositoryDocs(Document):
    """Store documentation for repositories"""

    repository_url: str = Field(..., description="URL of the GitHub repository")
    user_id: str = Field(..., description="GitHub ID of the user who created the docs")
    docs: QAResponse = Field(..., description="QA data for the repository")
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    updated_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))

    class Settings:
        name = "repository_docs"
        indexes = [
            "repository_url",
            "user_id",
            ("repository_url", "user_id"),  # Compound index
        ]

    @classmethod
    async def get_docs(cls, repository_url: str, user_id: str) -> Optional["RepositoryDocs"]:
        """Get docs for a repository and user"""
        return await cls.find_one({"repository_url": repository_url, "user_id": user_id})

    async def save_docs(self) -> None:
        """Save docs with updated timestamp"""
        self.updated_at = datetime.now(timezone.utc)
        await self.save()
