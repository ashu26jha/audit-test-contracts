from datetime import datetime, timezone
from typing import List, Optional

from beanie import Document, Indexed
from pydantic import BaseModel, ConfigDict, EmailStr, Field, field_serializer, field_validator


class SubscriptionData(BaseModel):
    """Represents user subscription information"""

    isActive: bool = False
    type: str = "single"  # "single" or "pro"
    credits: int = 0
    monthlyCredits: int = 0
    expiresAt: Optional[datetime] = None
    stripeSubscriptionId: Optional[str] = None
    stripeCustomerId: Optional[str] = None
    lastRenewalAt: Optional[datetime] = None

    @property
    def is_pro(self) -> bool:
        return self.type == "pro" and self.isActive

    # Validators to ensure UTC timezone
    @field_validator("expiresAt", "lastRenewalAt", mode="before")
    def ensure_utc(cls, v):
        if v is None:
            return v
        if isinstance(v, str):
            # Parse ISO format string to datetime
            try:
                v = datetime.fromisoformat(v.replace("Z", "+00:00"))
            except ValueError:
                try:
                    v = datetime.strptime(v, "%Y-%m-%dT%H:%M:%S.%f%z")
                except ValueError:
                    raise ValueError("Invalid datetime format")
        if isinstance(v, datetime):
            if v.tzinfo is None:
                v = v.replace(tzinfo=timezone.utc)
            return v.astimezone(timezone.utc)
        raise ValueError("Invalid datetime value")

    class Config:
        json_encoders = {
            datetime: lambda v: (
                v.isoformat() if v.tzinfo else v.replace(tzinfo=timezone.utc).isoformat()
            )
        }


class User(Document):
    """Main user document model for database storage"""

    username: str = Indexed(unique=True)
    email: EmailStr = Indexed(unique=True)
    githubId: str = Indexed(unique=True)
    accessToken: str
    avatarUrl: Optional[str] = None
    name: Optional[str] = None
    createdAt: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    updatedAt: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    installationId: Optional[List[int]] = Field(default_factory=list)
    token_version: int = Field(default=0)
    subscription: SubscriptionData = Field(default_factory=SubscriptionData)

    class Settings:
        name = "users"
        validate_on_save = True

    model_config = ConfigDict(
        json_schema_extra={
            "example": {
                "username": "johndoe",
                "email": "johndoe@example.com",
                "githubId": "12345678",
                "accessToken": "github_access_token_here",
                "avatarUrl": "https://avatars.githubusercontent.com/u/12345678?v=4",
                "name": "John Doe",
                "createdAt": datetime.now(timezone.utc),
                "updatedAt": datetime.now(timezone.utc),
                "installationId": [12345678],
                "token_version": 0,
                "subscription": {
                    "isActive": True,
                    "type": "pro",
                    "credits": 12,
                    "monthlyCredits": 12,
                    "expiresAt": datetime.now(timezone.utc),
                    "stripeSubscriptionId": "sub_xxxxxxxxxxxxx",
                    "lastRenewalAt": datetime.now(timezone.utc),
                },
            }
        }
    )

    # Validators to ensure UTC timezone
    @field_validator("createdAt", "updatedAt", mode="before")
    def ensure_utc(cls, v):
        if isinstance(v, datetime):
            if v.tzinfo is None:
                v = v.replace(tzinfo=timezone.utc)
            return v.astimezone(timezone.utc)
        return v

    # Serializers
    @field_serializer("createdAt", "updatedAt")
    def serialize_datetime(self, dt: datetime) -> str:
        """Serialize datetime to ISO format with UTC timezone"""
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        return dt.isoformat()

    # Query methods
    @classmethod
    async def by_email(cls, email: str) -> Optional["User"]:
        return await cls.find_one(cls.email == email)

    @classmethod
    async def by_github_id(cls, github_id: str) -> Optional["User"]:
        return await cls.find_one(cls.githubId == github_id)

    # Business logic methods
    async def ensure_token_version(self) -> None:
        """Ensure user has a token_version field"""
        if not hasattr(self, "token_version"):
            await self.update({"$set": {"token_version": 0}})

    async def has_active_subscription(self) -> bool:
        """Check if user has an active pro subscription with credits"""
        if not self.subscription.expiresAt:
            return False

        # All datetimes are guaranteed to be UTC at this point
        return (
            self.subscription.isActive
            and self.subscription.expiresAt > datetime.now(timezone.utc)
            and self.subscription.credits > 0
        )
