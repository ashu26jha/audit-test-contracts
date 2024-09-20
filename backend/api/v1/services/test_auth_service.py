from datetime import datetime, timedelta, timezone
from typing import Optional

import config.settings as settings
from api.v1.models.user import User
from bson import ObjectId
from jose import jwt


def create_test_access_token(data: dict, expires_delta: Optional[timedelta] = None):
    """Generate a JWT token for testing purposes."""
    to_encode = data.copy()
    expire = datetime.now(timezone.utc) + (expires_delta or timedelta(minutes=15))
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, settings.SECRET_KEY, algorithm=settings.ALGORITHM)
    return encoded_jwt


async def create_test_user(username: str) -> User:
    """Create a test user in the database."""
    test_user = User(
        id=ObjectId(),  # Generate a new ObjectId
        username=username,
        email=f"{username}@example.com",
        githubId="test_github_id",
        accessToken="test_access_token",
        createdAt=datetime.now(timezone.utc),
        updatedAt=datetime.now(timezone.utc),
    )
    await test_user.save()
    return test_user
