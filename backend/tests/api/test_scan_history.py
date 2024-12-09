from datetime import datetime, timezone
from unittest.mock import AsyncMock, MagicMock, patch
from uuid import uuid4

import pytest
from beanie import PydanticObjectId
from fastapi.testclient import TestClient

from api.v1.models.user import User
from api.v1.services import scan_history_service
from main import app


@pytest.fixture(scope="module")
def client():
    return TestClient(app)


@pytest.fixture
def mock_scan_history_service():
    with patch(
        "api.v1.endpoints.scan_history.get_scan_history_for_user", new_callable=AsyncMock
    ) as mock_service:
        yield mock_service


@pytest.mark.usefixtures("mock_auth")
class TestScanHistoryEndpoints:
    def test_get_scan_history(self, client, mock_scan_history_service):
        mock_scans = [
            {
                "scan_id": str(uuid4()),
                "scan_number": 1,
                "user_id": "612e3a5e630d2b1a6f20fb4b",
                "status": "completed",
                "startedAt": "2023-01-01T00:00:00Z",
                "completedAt": "2023-01-01T01:00:00Z",
                "createdAt": "2023-01-01T00:00:00Z",
                "updatedAt": "2023-01-01T01:00:00Z",
                "contractFiles": [],
                "branchName": "main",
                "commitHash": "abc123def",
                "paid_status": True,
            },
            {
                "scan_id": str(uuid4()),
                "scan_number": 2,
                "user_id": "612e3a5e630d2b1a6f20fb4b",
                "status": "in_progress",
                "startedAt": "2023-01-02T00:00:00Z",
                "completedAt": "2023-01-01T01:00:00Z",
                "createdAt": "2023-01-02T00:00:00Z",
                "updatedAt": "2023-01-02T01:00:00Z",
                "contractFiles": [],
                "branchName": "develop",
                "commitHash": "def456ghi",
                "paid_status": False,
            },
        ]
        mock_scan_history_service.return_value = mock_scans

        response = client.get("/api/v1/scans-history")
        assert response.status_code == 200
        response_data = response.json()
        assert response_data["success"]
        assert len(response_data["data"]) == 2
        assert response_data["data"][0]["scan_number"] == 1
        assert response_data["data"][1]["scan_number"] == 2

    def test_get_scan_history_empty(self, client, mock_scan_history_service):
        mock_scan_history_service.return_value = []

        response = client.get("/api/v1/scans-history")
        assert response.status_code == 200
        assert response.json() == {"success": True, "data": []}

    def test_get_scan_history_error(self, client, mock_scan_history_service):
        mock_scan_history_service.side_effect = Exception("Database error")

        response = client.get("/api/v1/scans-history")
        assert response.status_code == 500
        assert response.json() == {
            "success": False,
            "code": 500,
            "message": "An error occurred while fetching scan history",
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
            branchName="main",
            commitHash="abc123def",
            paid_status="paid",
        )

        mock_find = MagicMock()
        mock_sort = MagicMock()
        mock_to_list = AsyncMock(return_value=[mock_scan])

        mock_find.sort.return_value = mock_sort
        mock_sort.to_list = mock_to_list

        with patch("api.v1.models.scan.Scan.find", return_value=mock_find) as mocked_find:
            result = await scan_history_service.get_scan_history_for_user(mock_user)
            assert len(result) == 1
            assert result[0].scan_number == 1
            assert result[0].user_id == str(mock_user.githubId)

        # Verify that the find method was called with the correct arguments
        mocked_find.assert_called_once_with({"user_id": str(mock_user.githubId)})
        mock_to_list.assert_called_once()
