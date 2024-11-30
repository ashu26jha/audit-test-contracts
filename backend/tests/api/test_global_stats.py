from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from fastapi.testclient import TestClient

from config import settings
from main import app

client = TestClient(app)


@pytest.fixture
def mock_scan_aggregate():
    with patch("api.v1.models.scan.Scan.aggregate") as mock:
        mock_to_list = AsyncMock()
        mock_to_list.return_value = [
            {
                "total_scans": 100,
                "total_findings": 500,
                "total_lines_of_code": 10000,
                "paid_scans": 50,
                "discounted_scans": 10,
                "failed_scans": 5,
                "unpaid_completed_scans": 40,
            }
        ]
        mock.return_value.to_list = mock_to_list
        yield mock


@pytest.fixture
def mock_scan_find():
    with patch("api.v1.models.scan.Scan.find") as mock:
        mock_find_instance = MagicMock()
        # Define the side effects for each call to count()
        # The order of side effects should match the order of status queries
        mock_find_instance.count = AsyncMock(side_effect=[10, 20, 30, 5])
        mock.return_value = mock_find_instance
        yield mock


@pytest.mark.usefixtures("mock_auth")
def test_get_global_stats(mock_scan_aggregate, mock_scan_find):
    headers = {"x-api-key": settings.ADMIN_API_KEY}
    response = client.get("/api/v1/global-stats", headers=headers)

    assert response.status_code == 200
    result = response.json()
    assert result["success"] is True
    assert result["data"]["total_scans"] == 100
    assert result["data"]["total_paid_scans"] == {"total": 60, "regular_paid": 50, "discounted": 10}
    assert result["data"]["total_unpaid_scans"] == 40
    assert result["data"]["total_failed_scans"] == 5
    assert result["data"]["total_findings"] == 500
    assert result["data"]["total_lines_of_code"] == 10000
    assert result["data"]["scan_statuses"] == {
        "pending": 10,
        "in_progress": 20,
        "completed": 30,
        "failed": 5,
    }


def test_get_global_stats_error(mock_scan_aggregate):
    mock_scan_aggregate.side_effect = Exception("Database error")

    headers = {"x-api-key": settings.ADMIN_API_KEY}
    response = client.get("/api/v1/global-stats", headers=headers)
    assert response.status_code == 500
    error_response = response.json()
    assert error_response["success"] is False
    assert error_response["code"] == 500
    assert "An error occurred while fetching global stats" in error_response["message"]
    assert error_response["details"] is not None
