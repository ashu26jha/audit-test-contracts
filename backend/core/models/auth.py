from datetime import datetime, timezone
from typing import Optional

from beanie import Document
from pydantic import Field, field_validator
from pymongo import ASCENDING, IndexModel

from core.utils.ensure_utc import ensure_utc_datetime


class BlacklistedToken(Document):
    token: str = Field(index=True)
    blacklisted_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    expires_at: datetime

    @field_validator("blacklisted_at", "expires_at")
    @classmethod
    def ensure_utc(cls, v):
        return ensure_utc_datetime(v)

    class Settings:
        name = "blacklisted_tokens"
        indexes = [
            [("token", ASCENDING)],  # Index for token lookups
            IndexModel(
                [("expires_at", ASCENDING)], expireAfterSeconds=3600  # 1 hour
            ),  # TTL index based on expires_at
        ]


class LoginAttempt(Document):
    ip_address: str = Field(index=True)
    attempts: int = Field(default=0)
    last_attempt: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    blocked_until: Optional[datetime] = None

    @field_validator("last_attempt", "blocked_until")
    @classmethod
    def ensure_utc(cls, v):
        if v is not None:
            return ensure_utc_datetime(v)
        return v

    class Settings:
        name = "login_attempts"
        indexes = [
            [("ip_address", ASCENDING)],  # Index for IP lookups
            IndexModel(
                [("last_attempt", ASCENDING)], expireAfterSeconds=3600  # 1 hour
            ),  # TTL index
        ]


class OAuthState(Document):
    state: str = Field(index=True)
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    expires_at: datetime

    @field_validator("created_at", "expires_at")
    @classmethod
    def ensure_utc(cls, v):
        return ensure_utc_datetime(v)

    class Settings:
        name = "oauth_states"
        indexes = [
            [("state", ASCENDING)],  # Index for state lookups
            IndexModel(
                [("expires_at", ASCENDING)], expireAfterSeconds=300  # 5 minutes
            ),  # TTL index based on expires_at
        ]
