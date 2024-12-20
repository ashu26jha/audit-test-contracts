from datetime import datetime, timezone

from api.v1.models.user import SubscriptionData, User
from api.v1.schemas.user_schema import UserResponse


async def create_test_user(username: str) -> UserResponse:
    """Create a test user in the database."""
    test_user = User(
        username=username,
        email=f"{username}@example.com",
        githubId=f"test_{username}",
        accessToken="test_access_token",
        avatarUrl="https://github.com/ghost.png",
        name=username,
        createdAt=datetime.now(timezone.utc),
        updatedAt=datetime.now(timezone.utc),
        installationId=[12345],
        subscription=SubscriptionData(
            isActive=False,
            type="single",
            credits=0,
            monthlyCredits=0,
            expiresAt=None,
            stripeSubscriptionId=None,
            lastRenewalAt=None,
        ),
    )
    await test_user.save()
    return UserResponse.model_validate(test_user)
