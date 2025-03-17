from unittest.mock import AsyncMock, patch

import pytest

from api.v1.auth.service import is_internal_user
from core.models.user import SubscriptionData, SubscriptionType, User


@pytest.mark.asyncio
async def test_is_internal_user_with_oauth_token(setup_db):
    """Test is_internal_user method with OAuth token."""
    # Create a mock user with an access token
    user = User(
        username="testuser",
        email="test@example.com",
        githubId="12345",
        accessToken="oauth_token",
        subscription=SubscriptionData(
            isActive=True,
            type=SubscriptionType.FREE,
            credits=10,
            monthlyCredits=10,
        ),
    )

    # Create a user with Enterprise subscription for the return value
    enterprise_user = User(
        username="testuser",
        email="test@example.com",
        githubId="12345",
        accessToken="oauth_token",
        subscription=SubscriptionData(
            isActive=True,
            type=SubscriptionType.ENTERPRISE,
            credits=100,
            monthlyCredits=100,
        ),
    )

    # Mock the is_org_member method to return True
    with patch(
        "api.v1.github.helpers.github_api_client.GitHubAPIClient.is_org_member",
        AsyncMock(return_value=True),
    ), patch("config.settings.GITHUB_INTERNAL_ORG", "test-org"), patch(
        "core.db.repositories.user.UserRepository.activate_internal_subscription",
        AsyncMock(return_value=enterprise_user),
    ), patch(
        "core.db.repositories.user.UserRepository.deactivate_subscription",
        AsyncMock(return_value=None),
    ):
        result = await is_internal_user(user)

    # Assert the result
    assert result.is_internal is True
    assert result.subscription_activated is True
    assert result.subscription_downgraded is False


@pytest.mark.asyncio
async def test_is_internal_user_not_member(setup_db):
    """Test is_internal_user method when user is not a member."""
    # Create a mock user with an access token
    user = User(
        username="testuser",
        email="test@example.com",
        githubId="12345",
        accessToken="oauth_token",
        subscription=SubscriptionData(
            isActive=True,
            type=SubscriptionType.FREE,
            credits=10,
            monthlyCredits=10,
        ),
    )

    # Mock the is_org_member method to return False
    with patch(
        "api.v1.github.helpers.github_api_client.GitHubAPIClient.is_org_member",
        AsyncMock(return_value=False),
    ), patch("config.settings.GITHUB_INTERNAL_ORG", "test-org"):
        result = await is_internal_user(user)

    # Assert the result
    assert result.is_internal is False
    assert result.subscription_activated is False
    assert result.subscription_downgraded is False


@pytest.mark.asyncio
async def test_is_internal_user_no_token(setup_db):
    """Test is_internal_user method with no token."""
    # Create a mock user with no access token
    user = User(
        username="testuser",
        email="test@example.com",
        githubId="12345",
        accessToken=None,
        subscription=SubscriptionData(
            isActive=True,
            type=SubscriptionType.FREE,
            credits=10,
            monthlyCredits=10,
        ),
    )

    with patch("config.settings.GITHUB_INTERNAL_ORG", "test-org"):
        result = await is_internal_user(user)

    # Assert the result
    assert result.is_internal is False
    assert result.subscription_activated is False
    assert result.subscription_downgraded is False


@pytest.mark.asyncio
async def test_is_internal_user_no_org(setup_db):
    """Test is_internal_user method with no organization."""
    # Create a mock user with an access token
    user = User(
        username="testuser",
        email="test@example.com",
        githubId="12345",
        accessToken="oauth_token",
        subscription=SubscriptionData(
            isActive=True,
            type=SubscriptionType.FREE,
            credits=10,
            monthlyCredits=10,
        ),
    )

    with patch("config.settings.GITHUB_INTERNAL_ORG", ""):
        result = await is_internal_user(user)

    # Assert the result
    assert result.is_internal is False
    assert result.subscription_activated is False
    assert result.subscription_downgraded is False
