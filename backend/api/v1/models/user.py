from beanie import Document, Indexed
from pydantic import EmailStr
from datetime import datetime
from typing import Optional
from bson import ObjectId


class User(Document):
    username: Indexed(str, unique=True)
    email: Indexed(EmailStr, unique=True)
    githubId: Indexed(str, unique=True)
    accessToken: str
    createdAt: datetime = datetime.utcnow()
    updatedAt: datetime = datetime.utcnow()

    class Settings:
        name = "users"

    class Config:
        schema_extra = {
            "example": {
                "username": "johndoe",
                "email": "johndoe@example.com",
                "githubId": "12345678",
                "accessToken": "github_access_token_here",
                "createdAt": datetime.utcnow(),
                "updatedAt": datetime.utcnow()
            }
        }

    @classmethod
    async def by_email(cls, email: str) -> Optional["User"]:
        return await cls.find_one(cls.email == email)

    @classmethod
    async def by_github_id(cls, github_id: str) -> Optional["User"]:
        return await cls.find_one(cls.githubId == github_id)
