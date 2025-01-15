from datetime import datetime, timezone
from typing import Annotated, Optional

from beanie import Document, Indexed
from pydantic import Field, field_validator

from core.utils.ensure_utc import ensure_utc_datetime


class BlacklistedToken(Document):
    token: Annotated[str, Indexed()]
    blacklisted_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    expires_at: datetime

    # Add validators for all datetime fields
    @field_validator("blacklisted_at", "expires_at")
    @classmethod
    def ensure_utc(cls, v):
        return ensure_utc_datetime(v)

    class Settings:
        name = "blacklisted_tokens"
        indexes = [
            [("expires_at", 1)],  # Index for TTL
        ]


class LoginAttempt(Document):
    ip_address: str
    attempts: int = Field(default=0)
    last_attempt: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    blocked_until: Optional[datetime] = None

    # Add validators for all datetime fields
    @field_validator("last_attempt", "blocked_until")
    @classmethod
    def ensure_utc(cls, v):
        return ensure_utc_datetime(v)

    class Settings:
        name = "login_attempts"
        indexes = [
            [("last_attempt", 1)],
            [("blocked_until", 1)],
        ]


class OAuthState(Document):
    state: Annotated[str, Indexed()]
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    expires_at: datetime

    # Add validators for all datetime fields
    @field_validator("created_at", "expires_at")
    @classmethod
    def ensure_utc(cls, v):
        return ensure_utc_datetime(v)

    class Settings:
        name = "oauth_states"
        indexes = [
            [("expires_at", 1)],  # Index for TTL
        ]
