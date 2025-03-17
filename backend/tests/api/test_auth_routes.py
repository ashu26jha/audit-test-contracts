from unittest.mock import AsyncMock, patch

import pytest

from api.v1.auth.routes import check_internal_status
from api.v1.auth.schema import InternalUserResponse
from core.models.user import User


@pytest.mark.asyncio
async def test_check_internal_status_success(setup_db):
    """Test successful internal status check."""
    # Create a test user
    user = User(
        username="testuser",
        email="test@example.com",
        githubId="12345",
        accessToken="test_token",
    )

    # Mock the is_internal_user method to return a successful result
    mock_result = InternalUserResponse(
        is_internal=True, subscription_activated=True, subscription_downgraded=False
    )

    with patch("api.v1.auth.routes.is_internal_user", AsyncMock(return_value=mock_result)):
        response = await check_internal_status(user)

    # Assert the response
    assert response.success is True
    assert response.data == mock_result


@pytest.mark.asyncio
async def test_check_internal_status_not_internal(setup_db):
    """Test when user is not an internal organization member."""
    # Create a test user
    user = User(
        username="testuser",
        email="test@example.com",
        githubId="12345",
        accessToken="test_token",
    )

    # Mock the is_internal_user method to return a non-internal result
    mock_result = InternalUserResponse(
        is_internal=False, subscription_activated=False, subscription_downgraded=False
    )

    with patch("api.v1.auth.routes.is_internal_user", AsyncMock(return_value=mock_result)):
        response = await check_internal_status(user)

    # Assert the response
    assert response.success is True
    assert response.data == mock_result


@pytest.mark.asyncio
async def test_check_internal_status_downgraded(setup_db):
    """Test when user's subscription is downgraded."""
    # Create a test user
    user = User(
        username="testuser",
        email="test@example.com",
        githubId="12345",
        accessToken="test_token",
    )

    # Mock the is_internal_user method to return a downgraded result
    mock_result = InternalUserResponse(
        is_internal=False, subscription_activated=False, subscription_downgraded=True
    )

    with patch("api.v1.auth.routes.is_internal_user", AsyncMock(return_value=mock_result)):
        response = await check_internal_status(user)

    # Assert the response
    assert response.success is True
    assert response.data == mock_result
