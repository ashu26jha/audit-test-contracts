from datetime import datetime, timezone
from unittest.mock import AsyncMock, call, patch
from uuid import uuid4

import pytest
from fastapi.testclient import TestClient

from api.v1.models.payment import Payment, PaymentStatus, PaymentType
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
        payment_type=PaymentType.ONE_TIME,  # Add default payment type
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
    # Mock beanie document settings and Stripe event construction
    with patch("api.v1.models.payment.Payment.get_settings") as mock_settings, patch(
        "api.v1.models.payment.Payment.get_motor_collection"
    ) as mock_collection, patch("stripe.Webhook.construct_event") as mock_construct_event, patch(
        "api.v1.models.scan.Scan.find_one", new_callable=AsyncMock
    ) as mock_scan_find:

        # Setup mock returns
        mock_settings.return_value.motor_collection = AsyncMock()
        mock_collection.return_value = AsyncMock()
        mock_scan_find.return_value = AsyncMock(
            scan_id=str(uuid4()),
            user_id="test_user_123",
            status="completed",
            paid_status=False,
        )

        # Create a mock Stripe event
        mock_event = {
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
        mock_construct_event.return_value = mock_event

        # Create a mock Payment instance
        mock_payment = Payment(
            stripeSessionId="cs_test_123",
            scan_id=str(uuid4()),
            user_id="test_user_123",
            amount=0,
            currency="usd",
            status=PaymentStatus.PENDING,
            event_id="test_123",
            payment_type=PaymentType.ONE_TIME,
        )

        # Mock Payment.find_one and save methods
        with patch(
            "api.v1.models.payment.Payment.find_one", new_callable=AsyncMock
        ) as mock_payment_find, patch(
            "api.v1.models.payment.Payment.save", new_callable=AsyncMock
        ) as mock_save:
            # First call (duplicate check) should return None
            # Second call (finding payment by session ID) should return mock_payment
            mock_payment_find.side_effect = [None, mock_payment]
            mock_save.return_value = mock_payment

            # Mock the update_scan_paid_status
            with patch(
                "api.v1.services.scan_history_service.update_scan_paid_status",
                new_callable=AsyncMock,
            ):
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

                # Verify the payment was updated
                assert mock_payment.status == PaymentStatus.COMPLETED
                assert mock_payment.event_id == "evt_test_123"
                assert mock_payment.amount == amount / 100  # Convert back to dollars for comparison
                assert mock_payment.currency == "usd"
                assert mock_payment.updatedAt is not None

                # Verify both find_one calls were made with correct parameters
                assert mock_payment_find.call_count == 2
                mock_payment_find.assert_has_calls(
                    [
                        call({"event_id": "evt_test_123"}),  # First call: duplicate check
                        call({"stripeSessionId": "cs_test_123"}),  # Second call: find payment
                    ]
                )
                mock_save.assert_called_once()


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


@pytest.mark.asyncio
async def test_subscription_checkout_success(mock_user):
    # Mock beanie document settings and Stripe event construction
    with patch("api.v1.models.payment.Payment.get_settings") as mock_settings, patch(
        "api.v1.models.payment.Payment.get_motor_collection"
    ) as mock_collection, patch("stripe.Webhook.construct_event") as mock_construct_event, patch(
        "api.v1.models.user.User.by_github_id", new_callable=AsyncMock
    ) as mock_user_find, patch(
        "api.v1.models.user.User.save", new_callable=AsyncMock
    ) as mock_user_save, patch(
        "stripe.Customer.create"
    ) as mock_customer_create, patch(
        "stripe.Subscription.modify"
    ) as mock_subscription_modify:

        # Setup mock returns
        mock_settings.return_value.motor_collection = AsyncMock()
        mock_collection.return_value = AsyncMock()

        # Mock customer creation with proper Stripe-like object
        class MockStripeCustomer:
            id = "cus_123"

        mock_customer_create.return_value = MockStripeCustomer()

        # Mock subscription modification
        mock_subscription_modify.return_value = None

        # Use the mock_user fixture and add subscription data
        mock_user_find.return_value = mock_user

        # Create a mock subscription event
        mock_event = {
            "id": "evt_sub_123",
            "type": "checkout.session.completed",
            "data": {
                "object": {
                    "id": "cs_sub_123",
                    "mode": "subscription",
                    "customer": "cus_123",
                    "subscription": "sub_123",
                    "metadata": {"userId": mock_user.githubId},  # Use the mock user's ID
                }
            },
        }
        mock_construct_event.return_value = mock_event

        # Mock Payment.find_one to indicate no duplicate event
        with patch(
            "api.v1.models.payment.Payment.find_one", new_callable=AsyncMock
        ) as mock_payment_find:
            mock_payment_find.return_value = None

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

            # Verify user subscription was updated
            assert mock_user.subscription.isActive is True
            assert mock_user.subscription.type == "pro"
            assert mock_user.subscription.stripeSubscriptionId == "sub_123"
            assert mock_user.subscription.credits == SUBSCRIPTION_SETTINGS["pro"]["monthly_credits"]
            assert (
                mock_user.subscription.monthlyCredits
                == SUBSCRIPTION_SETTINGS["pro"]["monthly_credits"]
            )
            assert mock_user.subscription.lastRenewalAt is not None
            assert mock_user.subscription.expiresAt is not None
            mock_user_save.assert_called_once()

            # Verify Stripe API calls
            mock_customer_create.assert_called_once_with(
                email=mock_user.email, metadata={"githubId": mock_user.githubId}
            )
            mock_subscription_modify.assert_called_once_with(
                "sub_123", metadata={"userId": mock_user.githubId, "scanId": None}
            )


@pytest.mark.asyncio
async def test_subscription_checkout_failure():
    # Mock beanie document settings and Stripe event construction
    with patch("api.v1.models.payment.Payment.get_settings") as mock_settings, patch(
        "api.v1.models.payment.Payment.get_motor_collection"
    ) as mock_collection, patch("stripe.Webhook.construct_event") as mock_construct_event, patch(
        "api.v1.models.user.User.by_github_id", new_callable=AsyncMock
    ) as mock_user_find:

        # Setup mock returns
        mock_settings.return_value.motor_collection = AsyncMock()
        mock_collection.return_value = AsyncMock()
        mock_user_find.return_value = None  # Simulate user not found

        # Create a mock subscription event
        mock_event = {
            "id": "evt_sub_123",
            "type": "checkout.session.completed",
            "data": {
                "object": {
                    "id": "cs_sub_123",
                    "mode": "subscription",
                    "customer": "cus_123",
                    "subscription": "sub_123",
                    "metadata": {"userId": "nonexistent_user"},
                }
            },
        }
        mock_construct_event.return_value = mock_event

        # Mock Payment.find_one to indicate no duplicate event
        with patch(
            "api.v1.models.payment.Payment.find_one", new_callable=AsyncMock
        ) as mock_payment_find:
            mock_payment_find.return_value = None

            response = client.post(
                "/api/v1/payments/stripe-webhook",
                headers={"Stripe-Signature": "test_signature"},
                content=b"test_payload",
            )

            assert response.status_code == 200  # Webhook should still return 200 even on failure
            # Verify user was searched for but not found
            mock_user_find.assert_called_once_with("nonexistent_user")


@pytest.mark.asyncio
async def test_subscription_renewal_success():
    # Mock beanie document settings and Stripe event construction
    with patch("api.v1.models.payment.Payment.get_settings") as mock_settings, patch(
        "api.v1.models.payment.Payment.get_motor_collection"
    ) as mock_collection, patch("stripe.Webhook.construct_event") as mock_construct_event, patch(
        "api.v1.models.user.User.by_github_id", new_callable=AsyncMock
    ) as mock_user_find, patch(
        "api.v1.models.user.User.save", new_callable=AsyncMock
    ) as mock_user_save, patch(
        "stripe.Subscription.retrieve"
    ) as mock_subscription_retrieve, patch(
        "stripe.Customer.create"
    ) as mock_customer_create:

        # Setup mock returns
        mock_settings.return_value.motor_collection = AsyncMock()
        mock_collection.return_value = AsyncMock()
        mock_customer_create.return_value = {"id": "cus_123"}  # Mock customer creation response

        # Create a mock user with existing subscription
        mock_user = User(
            githubId="test_user_123",
            email="test@example.com",
            username="testuser",
            accessToken="test_token",  # Required field
            subscription={"isActive": True, "type": "pro", "credits": 0},
        )
        mock_user_find.return_value = mock_user

        # Mock subscription retrieval with proper Stripe-like object
        class MockStripeSubscription:
            metadata = {"userId": "test_user_123"}

        mock_subscription_retrieve.return_value = MockStripeSubscription()

        # Create a mock invoice payment event
        mock_event = {
            "id": "evt_inv_123",
            "type": "invoice.payment_succeeded",
            "data": {
                "object": {
                    "id": "in_123",
                    "subscription": "sub_123",
                    "customer": "cus_123",
                }
            },
        }
        mock_construct_event.return_value = mock_event

        # Mock Payment.find_one to indicate no duplicate event
        with patch(
            "api.v1.models.payment.Payment.find_one", new_callable=AsyncMock
        ) as mock_payment_find:
            mock_payment_find.return_value = None

            response = client.post(
                "/api/v1/payments/stripe-webhook",
                headers={"Stripe-Signature": "test_signature"},
                content=b"test_payload",
            )

            assert response.status_code == 200
            result = response.json()
            assert result["success"] is True

            # Verify user subscription was renewed
            assert mock_user.subscription.isActive is True
            assert mock_user.subscription.credits == SUBSCRIPTION_SETTINGS["pro"]["monthly_credits"]
            assert (
                mock_user.subscription.monthlyCredits
                == SUBSCRIPTION_SETTINGS["pro"]["monthly_credits"]
            )
            assert mock_user.subscription.lastRenewalAt is not None
            assert mock_user.subscription.expiresAt is not None
            mock_user_save.assert_called_once()


@pytest.mark.asyncio
async def test_subscription_renewal_failure():
    # Mock beanie document settings and Stripe event construction
    with patch("api.v1.models.payment.Payment.get_settings") as mock_settings, patch(
        "api.v1.models.payment.Payment.get_motor_collection"
    ) as mock_collection, patch("stripe.Webhook.construct_event") as mock_construct_event, patch(
        "api.v1.models.user.User.by_github_id", new_callable=AsyncMock
    ) as mock_user_find, patch(
        "stripe.Subscription.retrieve"
    ) as mock_subscription_retrieve:

        # Setup mock returns
        mock_settings.return_value.motor_collection = AsyncMock()
        mock_collection.return_value = AsyncMock()
        mock_user_find.return_value = None  # Simulate user not found

        # Mock subscription retrieval with proper Stripe-like object
        class MockStripeSubscription:
            metadata = {"userId": "nonexistent_user"}

        mock_subscription_retrieve.return_value = MockStripeSubscription()

        # Create a mock invoice payment event
        mock_event = {
            "id": "evt_inv_123",
            "type": "invoice.payment_succeeded",
            "data": {
                "object": {
                    "id": "in_123",
                    "subscription": "sub_123",
                    "customer": "cus_123",
                }
            },
        }
        mock_construct_event.return_value = mock_event

        # Mock Payment.find_one to indicate no duplicate event
        with patch(
            "api.v1.models.payment.Payment.find_one", new_callable=AsyncMock
        ) as mock_payment_find:
            mock_payment_find.return_value = None

            response = client.post(
                "/api/v1/payments/stripe-webhook",
                headers={"Stripe-Signature": "test_signature"},
                content=b"test_payload",
            )

            assert response.status_code == 200  # Webhook should still return 200 even on failure
            # Verify subscription was retrieved and user was searched for
            mock_subscription_retrieve.assert_called_once_with("sub_123")
            mock_user_find.assert_called_once_with("nonexistent_user")
