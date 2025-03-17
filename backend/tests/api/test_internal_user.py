from unittest.mock import AsyncMock, patch

import pytest

from api.v1.auth.service import is_internal_user
from core.models.user import SubscriptionData, SubscriptionType, User


@pytest.mark.asyncio
async def test_is_internal_user_not_internal(setup_db):
    """Test case where user is not an internal organization member."""
    # Create a test user
    user = User(
        username="testuser",
        email="test@example.com",
        githubId="12345",
        accessToken="test_token",
        subscription=SubscriptionData(
            isActive=False,
            type=SubscriptionType.FREE,
            credits=0,
            monthlyCredits=0,
        ),
    )

    # Mock the is_org_member method to return False
    with patch(
        "api.v1.github.helpers.github_api_client.GitHubAPIClient.is_org_member",
        AsyncMock(return_value=False),
    ):
        result = await is_internal_user(user)

    # Assert the result
    assert result.is_internal is False
    assert result.subscription_activated is False
    assert result.subscription_downgraded is False


@pytest.mark.asyncio
async def test_is_internal_user_case1_internal_without_enterprise(setup_db):
    """Test Case 1: User is internal and doesn't have Enterprise subscription."""
    # Create a test user with Free subscription
    user = User(
        username="testuser",
        email="test@example.com",
        githubId="12345",
        accessToken="test_token",
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
        accessToken="test_token",
        subscription=SubscriptionData(
            isActive=True,
            type=SubscriptionType.ENTERPRISE,
            credits=100,
            monthlyCredits=100,
        ),
    )

    # Mock the necessary methods
    with patch(
        "api.v1.github.helpers.github_api_client.GitHubAPIClient.is_org_member",
        AsyncMock(return_value=True),
    ), patch(
        "core.db.repositories.user.UserRepository.activate_internal_subscription",
        AsyncMock(return_value=enterprise_user),
    ):
        result = await is_internal_user(user)

    # Assert the result
    assert result.is_internal is True
    assert result.subscription_activated is True
    assert result.subscription_downgraded is False


@pytest.mark.asyncio
async def test_is_internal_user_case2_internal_with_enterprise_no_stripe(setup_db):
    """Test Case 2: User is internal and has Enterprise subscription without Stripe."""
    # Create a test user with Enterprise subscription but no Stripe ID
    user = User(
        username="testuser",
        email="test@example.com",
        githubId="12345",
        accessToken="test_token",
        subscription=SubscriptionData(
            isActive=True,
            type=SubscriptionType.ENTERPRISE,
            credits=100,
            monthlyCredits=100,
            stripeSubscriptionId=None,
        ),
    )

    # Mock the necessary methods
    with patch(
        "api.v1.github.helpers.github_api_client.GitHubAPIClient.is_org_member",
        AsyncMock(return_value=True),
    ):
        result = await is_internal_user(user)

    # Assert the result
    assert result.is_internal is True
    assert result.subscription_activated is True
    assert result.subscription_downgraded is False


@pytest.mark.asyncio
async def test_is_internal_user_case3_internal_with_enterprise_and_stripe(setup_db):
    """Test Case 3: User is internal and has Enterprise subscription through Stripe."""
    # Create a test user with Enterprise subscription and Stripe ID
    user = User(
        username="testuser",
        email="test@example.com",
        githubId="12345",
        accessToken="test_token",
        subscription=SubscriptionData(
            isActive=True,
            type=SubscriptionType.ENTERPRISE,
            credits=100,
            monthlyCredits=100,
            stripeSubscriptionId="sub_12345",
            stripeCustomerId="cus_12345",
        ),
    )

    # Create a user with Enterprise subscription but no Stripe ID for the return value
    updated_user = User(
        username="testuser",
        email="test@example.com",
        githubId="12345",
        accessToken="test_token",
        subscription=SubscriptionData(
            isActive=True,
            type=SubscriptionType.ENTERPRISE,
            credits=100,
            monthlyCredits=100,
            stripeSubscriptionId=None,
            stripeCustomerId="cus_12345",
        ),
    )

    # Mock the necessary methods
    with patch(
        "api.v1.github.helpers.github_api_client.GitHubAPIClient.is_org_member",
        AsyncMock(return_value=True),
    ), patch(
        "core.db.repositories.user.UserRepository.deactivate_subscription",
        AsyncMock(return_value=user),
    ), patch(
        "core.db.repositories.user.UserRepository.activate_internal_subscription",
        AsyncMock(return_value=updated_user),
    ):
        result = await is_internal_user(user)

    # Assert the result
    assert result.is_internal is True
    assert result.subscription_activated is True
    assert result.subscription_downgraded is False


@pytest.mark.asyncio
async def test_is_internal_user_case4_not_internal_with_enterprise_no_stripe(setup_db):
    """Test Case 4: User is not internal but has Enterprise subscription without Stripe ID."""
    # Create a test user with Enterprise subscription but no Stripe ID
    user = User(
        username="testuser",
        email="test@example.com",
        githubId="12345",
        accessToken="test_token",
        subscription=SubscriptionData(
            isActive=True,
            type=SubscriptionType.ENTERPRISE,
            credits=100,
            monthlyCredits=100,
            stripeSubscriptionId=None,
        ),
    )

    # Create a user with Free subscription for the return value
    free_user = User(
        username="testuser",
        email="test@example.com",
        githubId="12345",
        accessToken="test_token",
        subscription=SubscriptionData(
            isActive=True,
            type=SubscriptionType.FREE,
            credits=10,
            monthlyCredits=10,
        ),
    )

    # Mock the necessary methods
    with patch(
        "api.v1.github.helpers.github_api_client.GitHubAPIClient.is_org_member",
        AsyncMock(return_value=False),
    ), patch(
        "core.db.repositories.user.UserRepository.deactivate_subscription",
        AsyncMock(return_value=free_user),
    ):

        result = await is_internal_user(user)

    # Assert the result
    assert result.is_internal is False
    assert result.subscription_activated is False
    assert result.subscription_downgraded is True


@pytest.mark.asyncio
async def test_is_internal_user_not_internal_with_stripe_subscription(setup_db):
    """Test case where user is not internal and has a Stripe subscription."""
    # Create a test user with Enterprise subscription and Stripe ID
    user = User(
        username="testuser",
        email="test@example.com",
        githubId="12345",
        accessToken="test_token",
        subscription=SubscriptionData(
            isActive=True,
            type=SubscriptionType.ENTERPRISE,
            credits=100,
            monthlyCredits=100,
            stripeSubscriptionId="sub_12345",
            stripeCustomerId="cus_12345",
        ),
    )

    # Mock the necessary methods
    with patch(
        "api.v1.github.helpers.github_api_client.GitHubAPIClient.is_org_member",
        AsyncMock(return_value=False),
    ):
        result = await is_internal_user(user)

    # Assert the result - should not change subscription since it's a paid Stripe subscription
    assert result.is_internal is False
    assert result.subscription_activated is False
    assert result.subscription_downgraded is False


@pytest.mark.asyncio
async def test_is_internal_user_no_org_name(setup_db):
    """Test case where the organization name is not set."""
    # Create a test user
    user = User(
        username="testuser",
        email="test@example.com",
        githubId="12345",
        accessToken="test_token",
    )

    # Mock the settings to have no org name
    with patch("config.settings.GITHUB_INTERNAL_ORG", ""):
        result = await is_internal_user(user)

    # Assert the result
    assert result.is_internal is False
    assert result.subscription_activated is False
    assert result.subscription_downgraded is False


@pytest.mark.asyncio
async def test_is_internal_user_no_access_token(setup_db):
    """Test case where the user has no access token."""
    # Create a test user with no access token
    user = User(
        username="testuser",
        email="test@example.com",
        githubId="12345",
        accessToken=None,
    )

    result = await is_internal_user(user)

    # Assert the result
    assert result.is_internal is False
    assert result.subscription_activated is False
    assert result.subscription_downgraded is False
