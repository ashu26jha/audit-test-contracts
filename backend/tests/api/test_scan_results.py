# pylint: disable=redefined-outer-name,unused-argument
from datetime import datetime, timezone
from unittest.mock import AsyncMock, patch
from uuid import uuid4

import pytest
from beanie import PydanticObjectId
from fastapi import HTTPException
from fastapi.testclient import TestClient

from config import settings
from core.models.user import User
from main import app


@pytest.fixture(scope="module")
def client():
    return TestClient(app)


@pytest.fixture
def mock_get_current_user():
    with patch("api.v1.auth.helpers.dependencies.get_current_user", new_callable=AsyncMock) as mock:
        mock.return_value = User(
            id=PydanticObjectId(),
            username="testuser",
            email="testuser@example.com",
            githubId="test_github_id",
            accessToken="test_access_token",
            createdAt=datetime.now(timezone.utc),
            updatedAt=datetime.now(timezone.utc),
        )
        yield mock


@pytest.fixture
def mock_get_scan():
    with patch("core.db.repositories.scan.ScanRepository.get_scan", new_callable=AsyncMock) as mock:
        yield mock


@pytest.fixture
def mock_validate_user_scan_access():
    with patch("core.utils.validate.validate_user_scan_access", new_callable=AsyncMock) as mock:
        yield mock


@pytest.fixture
def mock_get_full_scan_result():
    with patch(
        "api.v1.scans.service.ScanResultService.get_full_result", new_callable=AsyncMock
    ) as mock:
        yield mock


@pytest.fixture
def mock_get_partial_scan_result():
    with patch(
        "api.v1.scans.service.ScanResultService.get_partial_result", new_callable=AsyncMock
    ) as mock:
        yield mock


@pytest.mark.usefixtures("mock_auth")
class TestScanResultsEndpoints:
    async def test_get_full_scan_result(
        self,
        client,
        mock_get_current_user,
        mock_get_full_scan_result,
    ):
        scan_id = uuid4()
        mock_result = {
            "scan": {
                "scan_id": str(scan_id),
                "user_id": "test_user_id",
                "status": "completed",
                "scan_number": 1,
                "startedAt": datetime.now(timezone.utc),
                "completedAt": datetime.now(timezone.utc),
                "createdAt": datetime.now(timezone.utc),
                "updatedAt": datetime.now(timezone.utc),
                "paid_status": True,
                "contractFiles": ["TestContract.sol"],
                "branchName": "main",
                "commitHash": "abc123",
                "repositoryURL": "https://github.com/test/repo",
                "repositoryName": "test-repo",
                "linesOfCode": None,
                "total_findings": 1,
                "progress": 1.0,
            },
            "result": {
                "scan_id": str(scan_id),
                "scan_number": 1,
                "summary": "Test summary",
                "type": "default",
                "total_findings": 1,
                "findings": [
                    {
                        "Issue": "Test issue",
                        "Severity": "High",
                        "Contracts": ["TestContract.sol"],
                        "Description": "Test description",
                        "Recommendation": "Test recommendation",
                    }
                ],
                "info_message": "Test info message",
                "createdAt": datetime.now(timezone.utc),
                "completedAt": datetime.now(timezone.utc),
            },
        }
        mock_get_full_scan_result.return_value = mock_result

        headers = {"x-api-key": settings.ADMIN_API_KEY}

        response = client.get(f"/api/v1/scans/result/{str(scan_id)}", headers=headers)

        assert response.status_code == 200
        result = response.json()
        assert result["success"] is True
        assert "data" in result
        data = result["data"]
        assert data["scan"]["scan_id"] == str(scan_id)
        assert data["result"]["summary"] == "Test summary"
        assert len(data["result"]["findings"]) == 1

    async def test_get_scan_result_not_found(
        self,
        client,
        mock_get_current_user,
        mock_get_full_scan_result,
    ):
        scan_id = uuid4()
        mock_get_full_scan_result.side_effect = HTTPException(
            status_code=404, detail=f"Scan with ID {scan_id} not found"
        )

        headers = {"x-api-key": settings.ADMIN_API_KEY}

        response = client.get(f"/api/v1/scans/result/{str(scan_id)}", headers=headers)
        assert response.status_code == 404
        assert not response.json()["success"]

    async def test_get_scan_result_unauthorized(
        self,
        client,
        mock_get_current_user,
        mock_get_full_scan_result,
    ):
        scan_id = uuid4()
        mock_get_full_scan_result.side_effect = HTTPException(
            status_code=403, detail="Unauthorized access"
        )

        headers = {"x-api-key": settings.ADMIN_API_KEY}

        response = client.get(f"/api/v1/scans/result/{str(scan_id)}", headers=headers)
        assert response.status_code == 403
        assert not response.json()["success"]
