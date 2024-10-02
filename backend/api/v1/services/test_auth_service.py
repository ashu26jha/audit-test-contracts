from datetime import datetime, timezone

from api.v1.models.user import User
from bson import ObjectId


async def create_test_user(username: str) -> User:
    """Create a test user in the database."""
    test_user = User(
        id=ObjectId(),
        username=username,
        email=f"{username}@example.com",
        githubId="test_github_id",
        accessToken="test_access_token",
        createdAt=datetime.now(timezone.utc),
        updatedAt=datetime.now(timezone.utc),
    )
    await test_user.save()
    return test_user
