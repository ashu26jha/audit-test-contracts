from unittest.mock import AsyncMock, patch

import pytest
from beanie import PydanticObjectId, init_beanie
from fastapi.testclient import TestClient
from mongomock_motor import AsyncMongoMockClient

from api.v1.auth.helpers.dependencies import get_current_user
from api.v1.router import router as api_v1_router
from core.models.payment import Payment
from core.models.scan import Scan, ScanResult
from core.models.user import User
from main import app


@pytest.fixture(scope="module")
def test_client():
    # Ensure routes are mounted
    app.include_router(api_v1_router)

    return TestClient(app)


@pytest.fixture
def mock_auth():
    with patch("core.models.user.User.get_motor_collection", new_callable=AsyncMock):
        with patch("core.models.user.User.get_settings") as mock_get_settings:
            mock_get_settings.return_value.motor_collection = AsyncMock()

            async def override_get_current_user():
                return User(
                    id=PydanticObjectId(),
                    username="testuser",
                    accessToken="test_token",
                    email="testuser@example.com",
                    githubId="test_github_id",
                )

            app.dependency_overrides[get_current_user] = override_get_current_user
            yield
            app.dependency_overrides.clear()


@pytest.fixture
async def setup_db():
    """Initialize mock database for tests"""
    client = AsyncMongoMockClient()
    db = client.get_database("test_db")

    # Initialize beanie with the mock client
    await init_beanie(database=db, document_models=[Payment, User, Scan, ScanResult])

    yield

    # Clean up
    client.close()
