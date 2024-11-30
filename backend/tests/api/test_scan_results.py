from datetime import datetime, timezone
from unittest.mock import AsyncMock, patch
from uuid import uuid4

import pytest
from beanie import PydanticObjectId
from fastapi import HTTPException
from fastapi.testclient import TestClient

from api.v1.models.scan import Scan, ScanResult
from api.v1.models.user import User
from api.v1.schemas.context_scan_schema import Finding
from config import settings
from main import app


@pytest.fixture(scope="module")
def client():
    return TestClient(app)


@pytest.fixture
def mock_get_current_user():
    with patch("api.v1.services.auth_service.get_current_user", new_callable=AsyncMock) as mock:
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
    with patch("api.v1.models.scan.Scan.get_settings") as mock_settings, patch(
        "api.v1.models.scan.Scan.get_motor_collection"
    ) as mock_collection, patch(
        "api.v1.services.scan_history_service.Scan.find_one", new_callable=AsyncMock
    ) as mock:

        mock_settings.return_value.motor_collection = AsyncMock()
        mock_collection.return_value = AsyncMock()

        mock_scan = Scan(
            scan_id=uuid4(),
            user_id="test_user_id",
            status="completed",
            scan_number=1,
            startedAt=datetime.now(timezone.utc),
            completedAt=datetime.now(timezone.utc),
            createdAt=datetime.now(timezone.utc),
            updatedAt=datetime.now(timezone.utc),
        )
        mock.return_value = mock_scan
        yield mock


@pytest.fixture
def mock_validate_user_scan_access():
    with patch(
        "api.v1.endpoints.scan_results.validate_user_scan_access", new_callable=AsyncMock
    ) as mock:
        yield mock


@pytest.fixture
def mock_get_full_scan_result():
    with patch(
        "api.v1.endpoints.scan_results.get_full_scan_result", new_callable=AsyncMock
    ) as mock:
        yield mock


@pytest.fixture
def mock_get_partial_scan_result():
    with patch(
        "api.v1.endpoints.scan_results.get_partial_scan_result", new_callable=AsyncMock
    ) as mock:
        yield mock


@pytest.fixture
def mock_validate_scan_paid():
    with patch("api.v1.endpoints.scan_results.validate_scan_paid", new_callable=AsyncMock) as mock:
        yield mock


@pytest.mark.usefixtures("mock_auth")
class TestScanResultsEndpoints:
    async def test_get_full_scan_result(
        self,
        client,
        mock_get_current_user,
        mock_get_scan,
        mock_validate_user_scan_access,
        mock_get_full_scan_result,
        mock_validate_scan_paid,
    ):
        scan_id = uuid4()
        mock_scan = Scan(
            scan_id=scan_id,
            user_id="test_user_id",
            status="completed",
            scan_number=1,
            startedAt=datetime.now(timezone.utc),
            completedAt=datetime.now(timezone.utc),
            createdAt=datetime.now(timezone.utc),
            updatedAt=datetime.now(timezone.utc),
            paid_status=True,
        )
        mock_get_scan.return_value = mock_scan

        mock_full_result = ScanResult(
            scan_id=scan_id,
            scan_number=1,
            summary="Test summary",
            type="default",
            total_findings=1,
            findings=[
                Finding(
                    Issue="Test issue",
                    Severity="High",
                    Contracts=["TestContract.sol"],
                    Description="Test description",
                    Recommendation="Test recommendation",
                )
            ],
            info_message="Test info message",
            createdAt=datetime.now(timezone.utc),
            completedAt=datetime.now(timezone.utc),
        )
        mock_get_full_scan_result.return_value = mock_full_result

        headers = {"x-api-key": settings.ADMIN_API_KEY}

        response = client.get(f"/api/v1/scans/full/{str(scan_id)}", headers=headers)

        assert response.status_code == 200
        data = response.json()["data"]
        assert data["scan"]["scan_id"] == str(scan_id)
        assert data["result"]["summary"] == "Test summary"
        assert len(data["result"]["findings"]) == 1

    async def test_get_partial_scan_result(
        self,
        client,
        mock_get_current_user,
        mock_get_scan,
        mock_validate_user_scan_access,
        mock_get_partial_scan_result,
    ):
        scan_id = uuid4()
        mock_scan = Scan(scan_id=scan_id, user_id="test_user_id", status="completed")
        mock_get_scan.return_value = mock_scan

        mock_partial_result = ScanResult(
            scan_id=scan_id,
            scan_number=1,
            summary="Test summary",
            type="default",
            findings=[
                Finding(
                    Issue="Test issue",
                    Severity="High",
                    Contracts=["TestContract.sol"],
                    Description="Test description",
                )
            ],
        )
        mock_get_partial_scan_result.return_value = mock_partial_result

        headers = {"x-api-key": settings.ADMIN_API_KEY}

        response = client.get(f"/api/v1/scans/partial/{str(scan_id)}", headers=headers)
        assert response.status_code == 200
        data = response.json()["data"]
        assert data["scan"]["scan_id"] == str(scan_id)
        assert data["partial_result"]["summary"] == "Test summary"
        assert len(data["partial_result"]["findings"]) == 1

    async def test_get_scan_result_not_found(self, client, mock_get_current_user, mock_get_scan):
        scan_id = uuid4()
        mock_get_scan.side_effect = HTTPException(
            status_code=404, detail=f"Scan with ID {scan_id} not found"
        )

        headers = {"x-api-key": settings.ADMIN_API_KEY}

        response = client.get(f"/api/v1/scans/full/{str(scan_id)}", headers=headers)
        assert response.status_code == 404
        assert response.json()["success"] == False

    async def test_get_scan_result_unauthorized(
        self, client, mock_get_current_user, mock_get_scan, mock_validate_user_scan_access
    ):
        scan_id = uuid4()
        mock_get_scan.return_value = Scan(
            scan_id=scan_id,
            user_id="other_user_id",
            status="completed",
            scan_number=1,
            startedAt=datetime.now(timezone.utc),
            completedAt=datetime.now(timezone.utc),
            createdAt=datetime.now(timezone.utc),
            updatedAt=datetime.now(timezone.utc),
        )
        mock_validate_user_scan_access.side_effect = HTTPException(
            status_code=403, detail="Unauthorized access"
        )

        headers = {"x-api-key": settings.ADMIN_API_KEY}

        response = client.get(f"/api/v1/scans/full/{str(scan_id)}", headers=headers)
        assert response.status_code == 403
        assert response.json()["success"] == False
