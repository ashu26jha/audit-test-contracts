from datetime import datetime, timezone
from typing import List, Optional

from beanie import Document, Indexed
from pydantic import BaseModel, ConfigDict, EmailStr, Field, field_serializer, field_validator


class SubscriptionData(BaseModel):
    """
    Represents user subscription information.
    Handles subscription status, credits, and related Stripe data.
    """

    isActive: bool = Field(default=False, description="Whether subscription is currently active")
    type: str = Field(default="single", description="Subscription type: 'single' or 'pro'")
    credits: int = Field(default=0, description="Current available credits")
    monthlyCredits: int = Field(default=0, description="Credits allocated per month")
    expiresAt: Optional[datetime] = Field(None, description="When current subscription period ends")
    stripeSubscriptionId: Optional[str] = Field(None, description="Stripe subscription ID")
    stripeCustomerId: Optional[str] = Field(None, description="Stripe customer ID")
    lastRenewalAt: Optional[datetime] = Field(None, description="Last subscription renewal date")

    @property
    def is_pro(self) -> bool:
        """Check if user has an active pro subscription."""
        return self.type == "pro" and self.isActive

    @field_validator("expiresAt", "lastRenewalAt", mode="before")
    @classmethod
    def ensure_utc(cls, v):
        """Ensure datetime fields are in UTC timezone."""
        if v is None:
            return v
        if isinstance(v, str):
            try:
                v = datetime.fromisoformat(v.replace("Z", "+00:00"))
            except ValueError:
                try:
                    v = datetime.strptime(v, "%Y-%m-%dT%H:%M:%S.%f%z")
                except ValueError as e:
                    raise ValueError("Invalid datetime format") from e
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
    """
    Main user document model for database storage.
    Handles user authentication, GitHub integration, and subscription management.
    """

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

    model_config = ConfigDict(
        json_schema_extra={
            "example": {
                "username": "johndoe",
                "email": "johndoe@example.com",
                "githubId": "12345678",
                "accessToken": "github_access_token_here",
                "avatarUrl": "https://avatars.githubusercontent.com/u/12345678?v=4",
                "name": "John Doe",
                "createdAt": "2023-10-01T12:00:00Z",
                "updatedAt": "2023-10-01T12:00:01Z",
                "installationId": [12345678],
                "token_version": 0,
                "subscription": {
                    "isActive": True,
                    "type": "pro",
                    "credits": 12,
                    "monthlyCredits": 12,
                    "expiresAt": "2023-10-01T12:00:02Z",
                    "stripeSubscriptionId": "sub_xxxxxxxxxxxxx",
                    "lastRenewalAt": "2023-10-01T12:00:03Z",
                },
            }
        }
    )

    class Settings:
        name = "users"
        validate_on_save = True
        indexes = [
            [("username", 1)],
            [("email", 1)],
            [("githubId", 1)],
            [("subscription.stripeCustomerId", 1)],
            [("subscription.stripeSubscriptionId", 1)],
            [("accessToken", 1)],
        ]

    @field_validator("createdAt", "updatedAt", mode="before")
    @classmethod
    def ensure_utc(cls, v):
        """Ensure datetime fields are in UTC timezone."""
        if isinstance(v, datetime):
            if v.tzinfo is None:
                v = v.replace(tzinfo=timezone.utc)
            return v.astimezone(timezone.utc)
        return v

    @field_serializer("createdAt", "updatedAt")
    @classmethod
    def serialize_datetime(cls, dt: datetime) -> str:
        """Serialize datetime to ISO format with UTC timezone."""
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        return dt.isoformat()

    async def ensure_token_version(self) -> None:
        """Ensure user has a token_version field."""
        if not hasattr(self, "token_version"):
            await self.update({"$set": {"token_version": 0}})

    async def has_active_subscription(self) -> bool:
        """
        Check if user has an active pro subscription with credits.
        Returns False if subscription is expired or out of credits.
        """
        # pylint: disable=no-member
        subscription: SubscriptionData = self.subscription
        if not subscription.expiresAt:
            return False

        return (
            subscription.isActive
            and subscription.expiresAt > datetime.now(timezone.utc)
            and subscription.credits > 0
        )
