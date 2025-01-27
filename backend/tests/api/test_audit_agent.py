# pylint: disable=redefined-outer-name
from datetime import datetime, timedelta, timezone
from unittest.mock import AsyncMock, MagicMock, patch
from uuid import UUID

import pytest
from fastapi.testclient import TestClient

from api.v1.audit_agent.schema import AuditAgentRequest
from api.v1.auth.helpers.dependencies import get_current_user
from config import settings
from core.models.user import SubscriptionData, SubscriptionType, User
from main import app

client = TestClient(app)


@pytest.fixture
def mock_create_scan():
    async def mock_impl(scan_id: UUID, user: User, request: AuditAgentRequest):
        # Calculate priority based on user type
        if user.is_enterprise:
            priority = 1  # Highest priority
        elif user.is_pro:
            priority = 5  # Medium priority
        else:
            priority = 10  # Lowest priority (default)

        # Queue the task with Huey
        from api.v1.audit_agent.service import perform_audit_agent_background

        perform_audit_agent_background(
            str(scan_id),
            str(user.githubId),
            user.email,
            user.accessToken,
            1,  # scan_number
            request.model_dump(),
            not user.is_free,  # is_subscription_scan
            None,  # formatted_docs
            priority=priority,
        )

    with patch(
        "api.v1.audit_agent.service.AuditAgentService.create_scan",
        new_callable=AsyncMock,
        side_effect=mock_impl,
    ) as mock:
        yield mock


class TestAuditAgentEndpoints:
    @pytest.mark.usefixtures("mock_auth")
    def test_perform_audit_agent_success(self, mock_create_scan):
        # Arrange
        request_payload = {
            "repositoryURL": "https://github.com/testowner/testrepo",
            "contractFiles": ["contracts/MyContract.sol"],
            "branchName": "main",
        }
        headers = {"x-api-key": settings.ADMIN_API_KEY}

        # Act
        response = client.post("/api/v1/audit-agent", json=request_payload, headers=headers)

        # Assert
        assert response.status_code == 202
        response_data = response.json()
        assert response_data["success"] is True
        assert "data" in response_data
        assert "scan_id" in response_data["data"]

        # Verify create_scan was called with correct argument types
        mock_create_scan.assert_awaited_once()
        call_args = mock_create_scan.await_args
        assert isinstance(call_args[0][0], UUID)  # scan_id
        assert isinstance(call_args[0][1], User)  # user
        assert isinstance(call_args[0][2], AuditAgentRequest)  # request

    @pytest.mark.usefixtures("mock_auth")
    def test_perform_audit_agent_invalid_input(self):
        # Arrange
        invalid_payload = {
            "repositoryURL": "https://github.com/testowner/testrepo",
            # Missing contractFiles and branchName
        }
        headers = {"x-api-key": settings.ADMIN_API_KEY}

        # Act
        response = client.post("/api/v1/audit-agent", json=invalid_payload, headers=headers)

        # Assert
        assert response.status_code == 422  # Unprocessable Entity
        response_data = response.json()
        assert response_data["success"] is False
        assert response_data["code"] == 422
        assert response_data["message"] == "Validation error"
        assert response_data["details"] is not None
        assert any("contractFiles" in detail["loc"] for detail in response_data["details"])

    @pytest.mark.asyncio
    async def test_scan_priority_queue(self, mock_create_scan):
        # Arrange
        headers = {"x-api-key": settings.ADMIN_API_KEY}
        base_payload = {
            "repositoryURL": "https://github.com/testowner/testrepo",
            "contractFiles": ["contracts/MyContract.sol"],
            "branchName": "main",
        }

        # Mock the database operations for User objects
        with patch("core.models.user.User.get_motor_collection", new_callable=AsyncMock), patch(
            "core.models.user.User.get_settings"
        ) as mock_get_settings, patch(
            "api.v1.audit_agent.service.perform_audit_agent_background"
        ) as mock_background:
            # Setup mocks
            mock_get_settings.return_value.motor_collection = AsyncMock()
            mock_background.return_value = MagicMock()

            # Create test users with different subscription levels
            enterprise_user = User(
                username="enterprise_user",
                email="enterprise@test.com",
                githubId="enterprise_id",
                accessToken="test_token",
                subscription=SubscriptionData(
                    type=SubscriptionType.ENTERPRISE,
                    isActive=True,
                    credits=10,
                    expiresAt=datetime.now(timezone.utc) + timedelta(days=30),
                ),
            )

            pro_user = User(
                username="pro_user",
                email="pro@test.com",
                githubId="pro_id",
                accessToken="test_token",
                subscription=SubscriptionData(
                    type=SubscriptionType.PRO,
                    isActive=True,
                    credits=10,
                    expiresAt=datetime.now(timezone.utc) + timedelta(days=30),
                ),
            )

            free_user = User(
                username="free_user",
                email="free@test.com",
                githubId="free_id",
                accessToken="test_token",
                subscription=SubscriptionData(type=SubscriptionType.FREE, isActive=True, credits=0),
            )

            # Test each user type
            for user, expected_priority in [
                (enterprise_user, 1),  # Enterprise - highest priority
                (pro_user, 5),  # Pro - medium priority
                (free_user, 10),  # Free - lowest priority
            ]:

                async def override_get_current_user():
                    return user

                # Override the dependency
                app.dependency_overrides[get_current_user] = override_get_current_user

                try:
                    response = client.post(
                        "/api/v1/audit-agent", json=base_payload, headers=headers
                    )
                    assert response.status_code == 202

                    # Verify create_scan was called with correct arguments
                    call = mock_create_scan.await_args_list[-1]
                    assert isinstance(call[0][0], UUID)  # scan_id
                    actual_user = call[0][1]
                    # Check important user fields instead of exact equality
                    assert actual_user.username == user.username
                    assert actual_user.email == user.email
                    assert actual_user.githubId == user.githubId
                    assert actual_user.subscription.type == user.subscription.type
                    assert actual_user.subscription.isActive == user.subscription.isActive
                    assert actual_user.subscription.credits == user.subscription.credits
                    assert isinstance(call[0][2], AuditAgentRequest)  # request

                    # Verify the task was scheduled with correct priority
                    background_call = mock_background.call_args_list[-1]
                    args = background_call[0]
                    assert isinstance(args[0], str)  # scan_id
                    assert args[1] == user.githubId  # user_id
                    assert args[2] == user.email  # user_email
                    assert args[3] == user.accessToken  # user_access_token
                    assert args[4] == 1  # scan_number
                    assert isinstance(args[5], dict)  # request_dict
                    assert args[6] == (not user.is_free)  # is_subscription_scan
                    assert args[7] is None  # formatted_docs
                    assert (
                        background_call[1]["priority"] == expected_priority
                    )  # Check priority kwarg
                finally:
                    # Clean up the override after each iteration
                    app.dependency_overrides.clear()

            # Verify that create_scan was called three times
            assert mock_create_scan.await_count == 3
            # Verify that schedule was called three times
            assert mock_background.call_count == 3

            # Verify the order of priorities (should be enterprise -> pro -> free)
            priorities = [call.kwargs["priority"] for call in mock_background.call_args_list]
            assert priorities == [1, 5, 10]
