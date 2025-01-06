from datetime import datetime, timezone
from typing import Dict, List

from beanie import Document
from pydantic import BaseModel, ConfigDict, Field


class QAResponse(BaseModel):
    readme: List[str] = Field(
        ...,
        description="Array of relative file paths within the repository (e.g., '/readme.md')",
    )
    qa: Dict[str, str]  # Mapping string keys to string values


class ReadmeDocs(Document):
    """Store documentation for repositories"""

    repository_url: str = Field(..., description="URL of the GitHub repository")
    user_id: str = Field(..., description="GitHub ID of the user who created the docs")
    docs: QAResponse = Field(..., description="QA data for the repository")
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    updated_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))

    model_config = ConfigDict(
        from_attributes=True,
        json_schema_extra={
            "example": {
                "repository_url": "https://github.com/user/repo",
                "user_id": "12345678",
                "docs": {
                    "readme": ["/README.md", "/docs/ARCHITECTURE.md"],
                    "qa": {
                        "What is this project?": "This is a smart contract project...",
                        "What are the main features?": "The main features include...",
                    },
                },
                "created_at": "2023-10-01T12:00:00Z",
                "updated_at": "2023-10-01T12:00:01Z",
            }
        },
    )

    class Settings:
        name = "repository_docs"
        validate_on_save = True
        indexes = [
            [("repository_url", 1)],
            [("user_id", 1)],
            [("repository_url", 1), ("user_id", 1)],
        ]
