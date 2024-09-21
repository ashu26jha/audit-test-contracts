from unittest.mock import AsyncMock, patch
from uuid import uuid4

import pytest
from bson import ObjectId
from fastapi.testclient import TestClient
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
            scan_id=uuid4(), user_id=str(ObjectId()), status="completed", paid_status=False
        )
        mock_find_user.return_value = AsyncMock(
            id=ObjectId(), email="test@example.com", username="testuser"
        )
        yield


def test_create_checkout_session(mock_stripe, mock_db):
    with patch(
        "api.v1.services.payment_service.PaymentService.create_checkout_session",
        new_callable=AsyncMock,
    ) as mock_create_session:
        mock_create_session.return_value = AsyncMock(id="test_session_id", url="https://test.com")

        response = client.post(
            "/api/v1/payments/create-checkout-session", json={"scanId": str(uuid4())}
        )
        assert response.status_code == 200
        assert "session_id" in response.json()
        assert "URL" in response.json()


@patch("api.v1.services.payment_service.stripe.Webhook.construct_event")
def test_webhook_handler(mock_construct_event, mock_db):
    mock_construct_event.return_value = {
        "type": "checkout.session.completed",
        "data": {
            "object": {
                "id": "test_session_id",
                "metadata": {"userId": str(ObjectId()), "scanId": str(uuid4())},
                "amount_total": 120,
                "currency": "usd",
            }
        },
    }

    with patch(
        "api.v1.services.payment_service.PaymentService.handle_webhook", new_callable=AsyncMock
    ) as mock_handle_webhook:
        mock_handle_webhook.return_value = True

        response = client.post(
            "/api/v1/payments/webhook",
            headers={"Stripe-Signature": "test_signature"},
            content=b"test_payload",
        )
        assert response.status_code == 200
        assert response.json() == {"success": True}


def test_payment_success():
    response = client.get("/api/v1/payments/payment_success?session_id=test_session_id")
    assert response.status_code == 201


def test_create_checkout_session_invalid_scan_id(mock_db):
    with patch(
        "api.v1.services.payment_service.PaymentService.create_checkout_session",
        new_callable=AsyncMock,
    ) as mock_create_session:
        mock_create_session.side_effect = ValueError("No scan found")

        response = client.post(
            "/api/v1/payments/create-checkout-session", json={"scanId": str(uuid4())}
        )
        assert response.status_code == 400
        assert "No scan found" in response.json()["detail"]


def test_webhook_handler_invalid_signature(mock_db):
    with patch(
        "api.v1.services.payment_service.PaymentService.handle_webhook", new_callable=AsyncMock
    ) as mock_handle_webhook:
        mock_handle_webhook.side_effect = ValueError("Invalid signature")

        response = client.post(
            "/api/v1/payments/webhook",
            headers={"Stripe-Signature": "invalid_signature"},
            content=b"test_payload",
        )
        assert response.status_code == 400
        assert "Invalid signature" in response.json()["detail"]
