from datetime import datetime, timezone
from typing import Annotated

from beanie import Document, Indexed
from pydantic import Field


class ThrottleRecord(Document):
    key: Annotated[str, Indexed()]
    request_count: int = Field(default=0)
    last_request: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    expires_at: datetime

    class Settings:
        name = "throttle_records"
        indexes = [
            [("expires_at", 1)],  # Index for TTL
        ]
