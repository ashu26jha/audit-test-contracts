from unittest.mock import AsyncMock, patch
from uuid import uuid4

import pytest
from bson import ObjectId
from fastapi.testclient import TestClient

from api.v1.models.payment import Payment, PaymentStatus
from main import app

client = TestClient(app)


@pytest.fixture
def mock_stripe():
    with patch("stripe.checkout.Session.create") as mock_create:
        mock_create.return_value = AsyncMock(id="test_session_id", url="https://test.com")
        yield mock_create


@pytest.fixture
def mock_db():
    with patch("api.v1.models.scan.Scan.find_one", new_callable=AsyncMock) as mock_find_scan, patch(
        "api.v1.models.user.User.find_one", new_callable=AsyncMock
    ) as mock_find_user, patch("api.v1.models.scan.Scan.save", new_callable=AsyncMock):

        mock_find_scan.return_value = AsyncMock(
            scan_id=uuid4(),
            user_id=str(ObjectId()),
            status="completed",
            paid_status=False,
        )
        mock_find_user.return_value = AsyncMock(
            id=ObjectId(), email="test@example.com", username="testuser"
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
        assert "URL" in result["data"]


@pytest.mark.asyncio
async def test_webhook_handler():
    # Mock beanie document settings
    with patch("api.v1.models.payment.Payment.get_settings") as mock_settings, patch(
        "api.v1.models.payment.Payment.get_motor_collection"
    ) as mock_collection, patch("stripe.Webhook.construct_event") as mock_construct_event:

        mock_settings.return_value.motor_collection = AsyncMock()
        mock_collection.return_value = AsyncMock()
        mock_construct_event.return_value = {
            "id": "evt_test_123",
            "type": "checkout.session.completed",
            "data": {
                "object": {
                    "id": "cs_test_123",
                    "payment_status": "paid",
                    "amount_total": 2000,
                    "currency": "usd",
                }
            },
        }

        # Create a proper Payment instance
        mock_payment = Payment(
            stripeSessionId="cs_test_123",
            scan_id=uuid4(),
            user_id=str(ObjectId()),
            amount=0,
            currency="usd",
            status=PaymentStatus.PENDING,
            event_id="",
        )

        # Mock the Payment.find_one method
        with patch(
            "api.v1.models.payment.Payment.find_one", new_callable=AsyncMock
        ) as mock_find_one, patch(
            "api.v1.models.payment.Payment.save", new_callable=AsyncMock
        ) as mock_save:

            mock_find_one.return_value = mock_payment

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
                                "amount_total": 2000,
                                "currency": "usd",
                            }
                        },
                    },
                )

                print(response.json())

                assert response.status_code == 200
                result = response.json()
                assert result["success"] is True
                assert "data" in result
                assert result["data"]["event_type"] == "checkout.session.completed"

                # Verify the payment was updated
                assert mock_payment.status == PaymentStatus.COMPLETED
                assert mock_payment.event_id == "evt_test_123"
                assert mock_payment.amount == 20
                assert mock_payment.currency == "usd"
                assert mock_payment.updatedAt is not None

                # Verify save was called
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
