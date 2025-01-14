from datetime import datetime
from typing import Annotated

from beanie import Document, Indexed


class ThrottleRecord(Document):
    key: Annotated[str, Indexed()]
    count: int
    last_request: datetime
    expires_at: datetime

    class Settings:
        name = "throttle_records"
        indexes = [
            [("expires_at", 1)],  # Index for TTL
        ]
