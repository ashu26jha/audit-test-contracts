# pylint: disable=redefined-outer-name
from datetime import datetime, timezone
from unittest.mock import AsyncMock, MagicMock, patch
from uuid import uuid4

import pytest
from beanie import PydanticObjectId
from fastapi.testclient import TestClient

from api.v1.scans.service import ScanHistoryService
from core.models.user import User
from core.utils.errors import QueryError
from main import app


@pytest.fixture(scope="module")
def client():
    return TestClient(app)


@pytest.fixture
def mock_scan_repository():
    with patch("core.db.repositories.scan.ScanRepository.get_scan_history") as mock_repo:
        mock_repo.return_value = AsyncMock()
        yield mock_repo


@pytest.mark.usefixtures("mock_auth")
class TestScanHistoryEndpoints:
    def test_get_scan_history(self, client, mock_scan_repository):
        mock_scans = [
            {
                "scan_id": str(uuid4()),
                "scan_number": 1,
                "user_id": "test_github_id",
                "status": "completed",
                "startedAt": "2023-01-01T00:00:00Z",
                "completedAt": "2023-01-01T01:00:00Z",
                "createdAt": "2023-01-01T00:00:00Z",
                "updatedAt": "2023-01-01T01:00:00Z",
                "contractFiles": [],
                "linesOfCode": None,
                "repositoryURL": None,
                "repositoryName": None,
                "branchName": "main",
                "commitHash": "abc123def",
                "paid_status": True,
                "total_findings": None,
                "progress": 0.0,
            },
            {
                "scan_id": str(uuid4()),
                "scan_number": 2,
                "user_id": "test_github_id",
                "status": "in_progress",
                "startedAt": "2023-01-02T00:00:00Z",
                "completedAt": None,
                "createdAt": "2023-01-02T00:00:00Z",
                "updatedAt": "2023-01-02T01:00:00Z",
                "contractFiles": [],
                "linesOfCode": None,
                "repositoryURL": None,
                "repositoryName": None,
                "branchName": "develop",
                "commitHash": "def456ghi",
                "paid_status": False,
                "total_findings": None,
                "progress": 0.0,
            },
        ]
        mock_scan_repository.return_value = mock_scans

        response = client.get("/api/v1/scans/history")
        assert response.status_code == 200
        response_data = response.json()
        assert response_data["success"]
        assert len(response_data["data"]) == 2
        assert response_data["data"][0]["scan_number"] == 1
        assert response_data["data"][1]["scan_number"] == 2

    def test_get_scan_history_empty(self, client, mock_scan_repository):
        mock_scan_repository.return_value = []

        response = client.get("/api/v1/scans/history")
        assert response.status_code == 200
        assert response.json() == {"success": True, "data": []}

    def test_get_scan_history_error(self, client, mock_scan_repository):
        mock_scan_repository.side_effect = QueryError(
            message="Failed to fetch scan history", details={"error": "Database error"}
        )

        response = client.get("/api/v1/scans/history")
        assert response.status_code == 500
        error_response = response.json()
        assert error_response == {
            "success": False,
            "code": 500,
            "message": "Failed to retrieve scan history",
            "details": None,
        }

    @pytest.mark.asyncio
    async def test_get_scan_history_service(self):
        mock_user = User(
            id=PydanticObjectId(),
            username="testuser",
            accessToken="test_token",
            email="test@example.com",
            githubId="test_github_id",
        )

        mock_scan = MagicMock(
            scan_id=uuid4(),
            scan_number=1,
            user_id=str(mock_user.githubId),
            status="completed",
            startedAt=datetime.now(timezone.utc),
            completedAt=datetime.now(timezone.utc),
            createdAt=datetime.now(timezone.utc),
            updatedAt=datetime.now(timezone.utc),
            contractFiles=[],
            linesOfCode=None,
            repositoryURL=None,
            repositoryName=None,
            branchName="main",
            commitHash="abc123def",
            paid_status=True,
            total_findings=None,
            progress=0.0,
        )

        mock_find = MagicMock()
        mock_sort = MagicMock()
        mock_to_list = AsyncMock(return_value=[mock_scan])

        mock_find.sort.return_value = mock_sort
        mock_sort.to_list = mock_to_list

        with patch("core.models.scan.Scan.find", return_value=mock_find) as mocked_find:
            result = await ScanHistoryService.get_scan_history_for_user(mock_user)
            assert len(result) == 1
            assert result[0].scan_number == 1
            assert result[0].user_id == str(mock_user.githubId)

        # Verify that the find method was called with the correct arguments
        mocked_find.assert_called_once_with({"user_id": str(mock_user.githubId)})
        mock_to_list.assert_called_once()
