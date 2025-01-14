from datetime import datetime
from typing import Annotated, Optional

from beanie import Document, Indexed


class BlacklistedToken(Document):
    token: Annotated[str, Indexed()]
    blacklisted_at: datetime
    expires_at: datetime

    class Settings:
        name = "blacklisted_tokens"
        indexes = [
            [("expires_at", 1)],  # Index for TTL
        ]


class LoginAttempt(Document):
    ip_address: Annotated[str, Indexed()]
    attempts: int
    last_attempt: datetime
    blocked_until: Optional[datetime] = None

    class Settings:
        name = "login_attempts"
        indexes = [
            [("last_attempt", 1)],
            [("blocked_until", 1)],
        ]


class OAuthState(Document):
    state: Annotated[str, Indexed()]
    created_at: datetime
    expires_at: datetime

    class Settings:
        name = "oauth_states"
        indexes = [
            [("expires_at", 1)],  # Index for TTL
        ]
