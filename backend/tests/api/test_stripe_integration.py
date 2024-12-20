from datetime import datetime, timezone
from unittest.mock import AsyncMock, patch
from uuid import uuid4

import pytest
from fastapi.testclient import TestClient

from api.v1.models.payment import Payment, PaymentStatus
from api.v1.models.user import User
from config.subscription_settings import SUBSCRIPTION_SETTINGS
from main import app

client = TestClient(app)
amount = SUBSCRIPTION_SETTINGS["single"]["price"] * 100  # Convert to cents for Stripe


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
        amount=amount,
        currency="USD",
        status=PaymentStatus.PENDING,
        createdAt=datetime.now(timezone.utc),
        updatedAt=datetime.now(timezone.utc),
        event_id="test_event",
        user_id="test_user_123",  # Using the same githubId as mock_user
        stripeSessionId="test_session",
    )


@pytest.fixture
def mock_db():
    with patch("api.v1.models.scan.Scan.find_one", new_callable=AsyncMock) as mock_find_scan, patch(
        "api.v1.models.user.User.find_one", new_callable=AsyncMock
    ) as mock_find_user, patch("api.v1.models.scan.Scan.save", new_callable=AsyncMock):

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


@pytest.mark.usefixtures("mock_auth")
def test_create_checkout_session():
    with patch(
        "api.v1.services.payments.stripe_session_service.StripeSessionService.create_checkout_session",
        new_callable=AsyncMock,
    ) as mock_create_session:
        mock_create_session.return_value = AsyncMock(id="test_session_id", url="https://test.com")

        response = client.post(
            "/api/v1/payments/create-stripe-session", json={"scanId": str(uuid4())}
        )
        assert response.status_code == 200
        result = response.json()
        assert result["success"] is True
        assert "data" in result
        assert "session_id" in result["data"]
        assert "url" in result["data"]


@pytest.mark.asyncio
async def test_webhook_handler():
    # Mock beanie document settings
    with patch("api.v1.models.payment.Payment.get_settings") as mock_settings, patch(
        "api.v1.models.payment.Payment.get_motor_collection"
    ) as mock_collection, patch("stripe.Webhook.construct_event") as mock_construct_event, patch(
        "api.v1.models.scan.Scan.find_one", new_callable=AsyncMock
    ) as mock_scan_find:

        mock_settings.return_value.motor_collection = AsyncMock()
        mock_collection.return_value = AsyncMock()
        mock_scan_find.return_value = AsyncMock(
            scan_id=str(uuid4()),
            user_id="test_user_123",
            status="completed",
            paid_status=False,
        )
        mock_construct_event.return_value = {
            "id": "evt_test_123",
            "type": "checkout.session.completed",
            "data": {
                "object": {
                    "id": "cs_test_123",
                    "payment_status": "paid",
                    "amount_total": amount,
                    "currency": "usd",
                }
            },
        }

        # Create a proper Payment instance
        mock_payment = Payment(
            stripeSessionId="cs_test_123",
            scan_id=str(uuid4()),
            user_id="test_user_123",  # Using the same githubId as mock_user
            amount=0,
            currency="usd",
            status=PaymentStatus.PENDING,
            event_id="test_123",
        )

        # Mock the Payment.find_one method
        with patch(
            "api.v1.models.payment.Payment.find_one", new_callable=AsyncMock
        ) as mock_payment_find, patch(
            "api.v1.models.payment.Payment.save", new_callable=AsyncMock
        ) as mock_save:
            mock_payment_find.side_effect = [
                None,
                mock_payment,
            ]  # First call returns None (duplicate check), second call returns the payment

            # Add this to properly mock the save method
            mock_save.return_value = mock_payment

            # Mock the update_scan_paid_status
            with patch(
                "api.v1.services.scan_history_service.update_scan_paid_status",
                new_callable=AsyncMock,
            ):
                response = client.post(
                    "/api/v1/payments/stripe-webhook",
                    headers={"Stripe-Signature": "test_signature"},
                    json={
                        "id": "evt_test_123",
                        "type": "checkout.session.completed",
                        "data": {
                            "object": {
                                "id": "cs_test_123",
                                "payment_status": "paid",
                                "amount_total": amount,
                                "currency": "usd",
                            }
                        },
                    },
                )

                assert response.status_code == 200
                result = response.json()
                assert result["success"] is True
                assert "data" in result
                assert result["data"]["event_type"] == "checkout.session.completed"

                # Verify the payment was updated
                assert mock_payment.status == PaymentStatus.COMPLETED
                assert mock_payment.event_id == "evt_test_123"
                assert mock_payment.amount == amount / 100  # Convert back to dollars for comparison
                assert mock_payment.currency == "usd"
                assert mock_payment.updatedAt is not None

                # Verify both find_one and save were called
                mock_payment_find.assert_called()
                mock_save.assert_called()


def test_webhook_handler_invalid_signature():
    with patch(
        "api.v1.services.payments.stripe_webhook_service.StripeWebhookService.handle_webhook",
        new_callable=AsyncMock,
    ) as mock_handle_webhook:
        mock_handle_webhook.side_effect = ValueError("Invalid signature")

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
def test_create_checkout_session_invalid_scan_id():
    with patch(
        "api.v1.services.payments.stripe_session_service.StripeSessionService.create_checkout_session",
        new_callable=AsyncMock,
    ) as mock_create_session:
        mock_create_session.side_effect = ValueError("No scan found")

        response = client.post(
            "/api/v1/payments/create-stripe-session", json={"scanId": str(uuid4())}
        )
        assert response.status_code == 400
        error_response = response.json()
        assert error_response["success"] is False
        assert error_response["code"] == 400
        assert "No scan found" in error_response["message"]
