from unittest.mock import AsyncMock, patch

import pytest
from beanie import PydanticObjectId
from fastapi.testclient import TestClient

from api.v1.models.payment import Payment
from api.v1.models.scan import Scan, ScanResult
from api.v1.models.user import User
from api.v1.services.auth_service import get_current_user
from main import app


@pytest.fixture(scope="module")
def test_client():
    return TestClient(app)


@pytest.fixture
def mock_auth():
    with patch("api.v1.models.user.User.get_motor_collection", new_callable=AsyncMock):
        with patch("api.v1.models.user.User.get_settings") as mock_get_settings:
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


@pytest.fixture(autouse=True)
async def mock_beanie_init():
    with patch("beanie.init_beanie", new_callable=AsyncMock) as mock_init_beanie:

        collections = [Scan, ScanResult, User, Payment]
        for collection in collections:
            collection._inheritance_inited = True
            collection.get_settings = AsyncMock()
            collection.get_motor_collection = AsyncMock()

        yield mock_init_beanie
