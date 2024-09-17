from datetime import datetime, timezone
from typing import Optional

from beanie import Document, Indexed
from pydantic import ConfigDict, EmailStr, Field


class User(Document):
    username: Indexed(str, unique=True)
    email: Indexed(EmailStr, unique=True)
    githubId: Indexed(str, unique=True)
    accessToken: str
    createdAt: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    updatedAt: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))

    class Settings:
        name = "users"

    model_config = ConfigDict(
        json_schema_extra={
            "example": {
                "username": "johndoe",
                "email": "johndoe@example.com",
                "githubId": "12345678",
                "accessToken": "github_access_token_here",
                "createdAt": datetime.now(timezone.utc),
                "updatedAt": datetime.now(timezone.utc),
            }
        }
    )

    @classmethod
    async def by_email(cls, email: str) -> Optional["User"]:
        return await cls.find_one(cls.email == email)

    @classmethod
    async def by_github_id(cls, github_id: str) -> Optional["User"]:
        return await cls.find_one(cls.githubId == github_id)
