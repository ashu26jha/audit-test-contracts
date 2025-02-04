from datetime import datetime, timezone
from typing import Annotated

from beanie import Document, Indexed
from pydantic import Field, field_validator
from pymongo import ASCENDING, IndexModel

from core.utils.ensure_utc import ensure_utc_datetime


class ThrottleRecord(Document):
    key: Annotated[str, Indexed()]
    request_count: int = Field(default=0)
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    last_request: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))

    @field_validator("created_at", "last_request")
    @classmethod
    def ensure_utc(cls, v):
        return ensure_utc_datetime(v)

    class Settings:
        name = "throttle_records"
        indexes = [
            [("key", ASCENDING)],  # Index for key lookups
            IndexModel([("created_at", ASCENDING)], expireAfterSeconds=60),
        ]
