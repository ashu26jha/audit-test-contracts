from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from api.v1.github.helpers.github_api_client import GitHubAPIClient


class MockResponse:
    def __init__(self, status_code, json_data=None):
        self.status_code = status_code
        self._json_data = json_data or {}

    def json(self):
        return self._json_data


@pytest.mark.asyncio
async def test_is_org_member_active(setup_db):
    """Test is_org_member method when user is an active member."""
    # Create an instance of GitHubAPIClient
    github_api_client = GitHubAPIClient()

    # Mock the get method to return user data with a login
    mock_user_data = {"login": "testuser"}

    # Mock the client.get method to return a 204 response (user is a member)
    mock_response = MagicMock()
    mock_response.status_code = 204

    with patch.object(
        github_api_client, "get", AsyncMock(return_value=mock_user_data)
    ), patch.object(github_api_client.client, "get", AsyncMock(return_value=mock_response)):
        result = await github_api_client.is_org_member("test_token", "test-org")

    # Assert the result
    assert result is True


@pytest.mark.asyncio
async def test_is_org_member_pending(setup_db):
    """Test is_org_member method when user has a pending membership."""
    # Create an instance of GitHubAPIClient
    github_api_client = GitHubAPIClient()

    # Mock the get method to return user data with a login
    mock_user_data = {"login": "testuser"}

    # Mock the client.get method to return a 204 response (user is a member)
    mock_response = MagicMock()
    mock_response.status_code = 204

    with patch.object(
        github_api_client, "get", AsyncMock(return_value=mock_user_data)
    ), patch.object(github_api_client.client, "get", AsyncMock(return_value=mock_response)):
        result = await github_api_client.is_org_member("test_token", "test-org")

    # Assert the result
    assert result is True


@pytest.mark.asyncio
async def test_is_org_member_not_member(setup_db):
    """Test is_org_member method when user is not a member."""
    # Create an instance of GitHubAPIClient
    github_api_client = GitHubAPIClient()

    # Mock the get method to return user data with a login
    mock_user_data = {"login": "testuser"}

    # Mock the client.get method to return a 404 response
    mock_response = MockResponse(404)

    with patch.object(
        github_api_client, "get", AsyncMock(return_value=mock_user_data)
    ), patch.object(github_api_client.client, "get", AsyncMock(return_value=mock_response)):
        result = await github_api_client.is_org_member("test_token", "test-org")

    # Assert the result
    assert result is False


@pytest.mark.asyncio
async def test_is_org_member_other_state(setup_db):
    """Test is_org_member method when user has a different state."""
    # Create an instance of GitHubAPIClient
    github_api_client = GitHubAPIClient()

    # Mock the get method to return user data with a login
    mock_user_data = {"login": "testuser"}

    # Mock the client.get method to return a non-204 response (user is not a member)
    mock_response = MagicMock()
    mock_response.status_code = 200  # Any status code other than 204

    with patch.object(
        github_api_client, "get", AsyncMock(return_value=mock_user_data)
    ), patch.object(github_api_client.client, "get", AsyncMock(return_value=mock_response)):
        result = await github_api_client.is_org_member("test_token", "test-org")

    # Assert the result
    assert result is False


@pytest.mark.asyncio
async def test_is_org_member_exception(setup_db):
    """Test is_org_member method when an exception occurs."""
    # Create an instance of GitHubAPIClient
    github_api_client = GitHubAPIClient()

    # Mock the get method to raise an exception
    with patch.object(
        github_api_client, "get", AsyncMock(side_effect=Exception("Test exception"))
    ), patch("api.v1.github.helpers.github_api_client.logger.warning") as mock_logger:

        result = await github_api_client.is_org_member("test_token", "test-org")

        # Assert the result
        assert result is False

        # Verify that the error was logged
        mock_logger.assert_called_once()
        assert "Error checking organization membership" in mock_logger.call_args[0][0]
