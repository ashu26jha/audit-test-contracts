# pylint: disable=too-many-ancestors,too-few-public-methods
from datetime import datetime, timezone
from typing import Optional

from beanie import Document, Indexed
from pydantic import ConfigDict, EmailStr, Field, field_serializer


class User(Document):
    username: str = Indexed(unique=True)
    email: EmailStr = Indexed(unique=True)
    githubId: str = Indexed(unique=True)
    accessToken: str
    avatarUrl: Optional[str] = None
    name: Optional[str] = None
    createdAt: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    updatedAt: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    installationId: list[int] = []

    class Settings:
        name = "users"

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
            }
        }
    )

    @field_serializer("createdAt", "updatedAt")
    def serialize_datetime(self, dt: datetime):
        return dt.isoformat()

    @classmethod
    async def by_email(cls, email: str) -> Optional["User"]:
        return await cls.find_one(cls.email == email)

    @classmethod
    async def by_github_id(cls, github_id: str) -> Optional["User"]:
        return await cls.find_one(cls.githubId == github_id)
