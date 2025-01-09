# pylint: disable=redefined-outer-name
from datetime import datetime, timezone
from unittest.mock import AsyncMock, patch
from uuid import uuid4

import pytest
from fastapi import HTTPException
from fastapi.testclient import TestClient

from config.subscription_settings import SUBSCRIPTION_SETTINGS
from core.models.payment import Payment, PaymentStatus, PaymentType
from core.models.user import User
from main import app

client = TestClient(app)
AMOUNT = SUBSCRIPTION_SETTINGS["free"]["price"] * 100  # Convert to cents for Stripe


@pytest.fixture
def mock_stripe():
    with patch("stripe.checkout.Session.create") as mock_create:
        mock_create.return_value = AsyncMock(id="test_session_id", url="https://test.com")
        yield mock_create


@pytest.fixture
async def mock_user():
    user = User(
        email="test@example.com",
        username="testuser",
        githubId="test_user_123",  # Using a predictable githubId for tests
        accessToken="test_token",
        createdAt=datetime.now(timezone.utc),
        updatedAt=datetime.now(timezone.utc),
    )
    return user


@pytest.fixture
async def mock_payment():
    return Payment(
        scan_id="test_scan_123",
        amount=AMOUNT,
        currency="USD",
        status=PaymentStatus.PENDING,
        createdAt=datetime.now(timezone.utc),
        updatedAt=datetime.now(timezone.utc),
        event_id="test_event",
        user_id="test_user_123",  # Using the same githubId as mock_user
        stripeSessionId="test_session",
        payment_type=PaymentType.ONE_TIME,  # Add default payment type
    )


@pytest.fixture
def mock_db():
    with patch("core.models.scan.Scan.find_one", new_callable=AsyncMock) as mock_find_scan, patch(
        "core.models.user.User.find_one", new_callable=AsyncMock
    ) as mock_find_user, patch("core.models.scan.Scan.save", new_callable=AsyncMock):
        mock_find_scan.return_value = AsyncMock(
            scan_id=str(uuid4()),
            user_id="test_user_123",  # Using the same githubId as mock_user
            status="completed",
            paid_status=False,
        )
        mock_find_user.return_value = AsyncMock(
            githubId="test_user_123", email="test@example.com", username="testuser"
        )
        yield


@pytest.mark.asyncio
async def test_webhook_handler():
    # Mock beanie document settings and Stripe event construction
    with patch(
        "api.v1.payments.service.StripeWebhookService.handle_webhook",
        new_callable=AsyncMock,
    ) as mock_handle_webhook:
        mock_event = {
            "id": "evt_test_123",
            "type": "checkout.session.completed",
        }
        mock_handle_webhook.return_value = mock_event

        response = client.post(
            "/api/v1/payments/stripe-webhook",
            headers={"Stripe-Signature": "test_signature"},
            content=b"test_payload",
        )

        assert response.status_code == 200
        result = response.json()
        assert result["success"] is True
        assert "data" in result
        assert result["data"]["event_type"] == "checkout.session.completed"


@pytest.mark.usefixtures("mock_auth")
def test_webhook_handler_invalid_signature():
    with patch(
        "api.v1.payments.service.StripeWebhookService.handle_webhook",
        new_callable=AsyncMock,
    ) as mock_handle_webhook:
        mock_handle_webhook.side_effect = HTTPException(status_code=400, detail="Invalid signature")

        response = client.post(
            "/api/v1/payments/stripe-webhook",
            headers={"Stripe-Signature": "invalid_signature"},
            content=b"test_payload",
        )
        assert response.status_code == 400
        error_response = response.json()
        assert error_response["success"] is False
        assert error_response["code"] == 400
        assert "Invalid signature" in error_response["message"]


@pytest.mark.usefixtures("mock_auth")
@pytest.mark.asyncio
async def test_subscription_checkout_success(mock_user):
    with patch(
        "api.v1.auth.helpers.dependencies.get_current_user", new_callable=AsyncMock
    ) as mock_get_user, patch(
        "api.v1.payments.service.StripeSubscriptionService.create_subscription_session",
        new_callable=AsyncMock,
    ) as mock_create_session:
        mock_get_user.return_value = mock_user
        mock_create_session.return_value = AsyncMock(id="test_session_id", url="https://test.com")

        response = client.post(
            "/api/v1/payments/create-subscription-session", json={"scanId": str(uuid4())}
        )
        assert response.status_code == 200
        result = response.json()
        assert result["success"] is True
        assert "data" in result
        assert "session_id" in result["data"]
        assert "url" in result["data"]


@pytest.mark.usefixtures("mock_auth")
@pytest.mark.asyncio
async def test_subscription_checkout_failure(mock_user):
    with patch(
        "api.v1.auth.helpers.dependencies.get_current_user", new_callable=AsyncMock
    ) as mock_get_user, patch(
        "api.v1.payments.service.StripeSubscriptionService.create_subscription_session",
        new_callable=AsyncMock,
    ) as mock_create_session:
        mock_get_user.return_value = mock_user
        mock_create_session.side_effect = HTTPException(
            status_code=400, detail="Already have an active subscription"
        )

        response = client.post(
            "/api/v1/payments/create-subscription-session", json={"scanId": str(uuid4())}
        )
        assert response.status_code == 400
        error_response = response.json()
        assert error_response["success"] is False
        assert error_response["code"] == 400
        assert "Already have an active subscription" in error_response["message"]


@pytest.mark.usefixtures("mock_auth")
@pytest.mark.asyncio
async def test_create_portal_session(mock_user):
    with patch(
        "api.v1.auth.helpers.dependencies.get_current_user", new_callable=AsyncMock
    ) as mock_get_user, patch(
        "api.v1.payments.service.StripeSubscriptionService.create_portal_session",
        new_callable=AsyncMock,
    ) as mock_create_session:
        mock_get_user.return_value = mock_user
        mock_create_session.return_value = AsyncMock(url="https://test.com")

        response = client.post("/api/v1/payments/create-portal-session")
        assert response.status_code == 200
        result = response.json()
        assert result["success"] is True
        assert "data" in result
        assert "url" in result["data"]
        assert result["data"]["url"] == "https://test.com"


@pytest.mark.usefixtures("mock_auth")
@pytest.mark.asyncio
async def test_create_portal_session_failure(mock_user):
    with patch(
        "api.v1.auth.helpers.dependencies.get_current_user", new_callable=AsyncMock
    ) as mock_get_user, patch(
        "api.v1.payments.service.StripeSubscriptionService.create_portal_session",
        new_callable=AsyncMock,
    ) as mock_create_session:
        mock_get_user.return_value = mock_user
        mock_create_session.side_effect = HTTPException(
            status_code=400, detail="No active subscription found"
        )

        response = client.post("/api/v1/payments/create-portal-session")
        assert response.status_code == 400
        error_response = response.json()
        assert error_response["success"] is False
        assert error_response["code"] == 400
        assert "No active subscription found" in error_response["message"]
