# pylint: disable=redefined-outer-name
from unittest.mock import AsyncMock, patch
from uuid import UUID

import pytest
from fastapi import BackgroundTasks
from fastapi.testclient import TestClient

from api.v1.audit_agent.schema import AuditAgentRequest
from config import settings
from core.models.user import User
from main import app

client = TestClient(app)


@pytest.fixture
def mock_create_scan():
    with patch(
        "api.v1.audit_agent.service.AuditAgentService.create_scan", new_callable=AsyncMock
    ) as mock:
        yield mock


@pytest.mark.usefixtures("mock_auth")
class TestAuditAgentEndpoints:
    def test_perform_audit_agent_success(self, mock_create_scan):
        # Arrange
        mock_create_scan.return_value = None

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
        assert isinstance(call_args[0][3], BackgroundTasks)  # background_tasks

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
