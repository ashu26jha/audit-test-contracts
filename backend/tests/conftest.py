from unittest.mock import AsyncMock, patch

import pytest
from beanie import PydanticObjectId, init_beanie
from fastapi.testclient import TestClient
from mongomock_motor import AsyncMongoMockClient

from api.v1.auth.helpers.dependencies import get_current_user
from core.models.auth import BlacklistedToken, LoginAttempt, OAuthState
from core.models.credit_transaction import CreditTransaction
from core.models.docs import ReadmeDocs
from core.models.payment import Payment
from core.models.scan import Scan, ScanResult
from core.models.throttling import ThrottleRecord
from core.models.user import User
from main import app

# Test constants
TEST_JWT_TOKEN = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJ0ZXN0X3Rlc3R1c2VyIiwidmVyc2lvbiI6NCwiZXhwIjoxNzEmnqdN_X80A79_K70XI"
TEST_API_KEY = "sk-test-key"

# Configure VCR for GitHub API tests
vcr_config = {
    "filter_headers": ["authorization", "cookie"],  # Don't record sensitive headers
    "record_mode": "once",  # Record once and reuse forever unless cassette is deleted
    "match_on": [
        "method",
        "scheme",
        "host",
        "port",
        "path",  # Include path but not query parameters
    ],
    "cassette_library_dir": "backend/tests/cassettes/github",
    "decode_compressed_response": True,
    "before_record_request": lambda request: request,
    "before_record_response": lambda response: response,
}

# Mock response for LLM calls
MOCK_LLM_RESPONSE = {
    "findings": [],
    "summary": "Mocked response for testing",
    "confidence_score": 0.8,
    "severity": "LOW",
    "title": "Mock Finding",
    "description": "This is a mock response for testing purposes",
    "recommendation": "No action needed - this is a test",
}


@pytest.fixture(autouse=True)
def mock_api_key():
    """Mock API key for all tests."""
    with patch("config.settings.ADMIN_API_KEY", TEST_API_KEY):
        yield


@pytest.fixture(autouse=True)
def mock_llm_calls():
    """Mock all LLM API calls"""
    with patch(
        "core.llm.send_prompt_to_llm.send_prompt_to_llm_async", return_value=MOCK_LLM_RESPONSE
    ):
        yield


@pytest.fixture
def auth_token():
    """Get a real JWT token from the test-auth endpoint."""
    with patch("config.settings.ADMIN_API_KEY", TEST_API_KEY):
        client = TestClient(app)
        response = client.post(
            "/api/v1/auth/test-auth/token",
            json={"username": "testuser"},
            headers={
                "x-api-key": TEST_API_KEY,
                "Content-Type": "application/json",
                "Accept": "application/json",
            },
        )
        assert response.status_code == 200, f"Failed to get auth token: {response.text}"
        data = response.json()
        token = data["data"]["access_token"]
        assert token is not None, "No access_token in response data"
        return token


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
def mock_stripe():
    """Mock Stripe API calls."""
    with patch("api.v1.payments.routes.StripeSubscriptionService") as mock_stripe:
        # Create a mock session with proper string values
        mock_session = AsyncMock()
        mock_session.id = "test_session_id"
        mock_session.url = "https://test.stripe.com/checkout"

        # Configure the mock to return our session using async methods
        async def mock_create_subscription_session(*args, **kwargs):
            return mock_session

        async def mock_create_portal_session(*args, **kwargs):
            return mock_session

        async def mock_create_enterprise_subscription_session(*args, **kwargs):
            return mock_session

        mock_stripe.create_subscription_session = mock_create_subscription_session
        mock_stripe.create_portal_session = mock_create_portal_session
        mock_stripe.create_enterprise_subscription_session = (
            mock_create_enterprise_subscription_session
        )
        yield mock_stripe


@pytest.fixture
async def setup_db():
    """Initialize mock database for tests"""
    client = AsyncMongoMockClient()
    db = client.get_database("test_db")

    # Initialize beanie with the mock client
    await init_beanie(
        database=db,
        document_models=[
            User,
            Scan,
            ScanResult,
            Payment,
            CreditTransaction,
            ReadmeDocs,
            BlacklistedToken,
            LoginAttempt,
            OAuthState,
            ThrottleRecord,
        ],
    )

    yield

    # Clean up
    client.close()


@pytest.fixture(autouse=True)
def mock_email_functions():
    """Mock all email sending functionality."""
    with patch("core.utils.email_utils.send_pdf_email", new_callable=AsyncMock) as mock_pdf, patch(
        "core.utils.email_utils.send_error_email", new_callable=AsyncMock
    ) as mock_error, patch(
        "core.utils.email_utils.send_failed_refund_email", new_callable=AsyncMock
    ) as mock_refund:
        mock_pdf.return_value = None
        mock_error.return_value = None
        mock_refund.return_value = None
        yield {"pdf": mock_pdf, "error": mock_error, "refund": mock_refund}
