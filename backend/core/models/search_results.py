from datetime import datetime, timezone

from beanie import Document
from pydantic import ConfigDict, Field, field_validator

from core.utils.ensure_utc import ensure_utc_datetime


class CachedContent(Document):
    """Store cached content for a given link."""

    link: str = Field(..., description="The URL of the cached content")
    content: str = Field(..., description="The content fetched from the link")
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    updated_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))

    model_config = ConfigDict(
        from_attributes=True,
        json_schema_extra={
            "example": {
                "link": "https://example.com",
                "content": "This is the cached content of the page.",
                "created_at": "2024-10-01T12:00:00Z",
                "updated_at": "2024-11-01T12:00:01Z",
            }
        },
    )

    @field_validator("created_at", "updated_at", mode="before")
    @classmethod
    def ensure_utc(cls, v):
        return ensure_utc_datetime(v)

    class Settings:
        name = "cached_contents"
        validate_on_save = True
        indexes = [
            [("link", 1)],
        ]
