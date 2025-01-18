import json
import time
from unittest.mock import AsyncMock, patch

import pytest
from beanie import init_beanie
from mongomock_motor import AsyncMongoMockClient

from api.v1.payments.helpers.stripe_webhook import StripeWebhookHelper
from api.v1.payments.service import StripeWebhookService
from core.db.repositories.user import UserRepository
from core.models.payment import Payment
from core.models.scan import Scan
from core.models.user import User


@pytest.fixture(autouse=True)
async def setup_db():
    """Initialize test database using mongomock"""
    client = AsyncMongoMockClient()
    db = client.get_database("test_db")

    await init_beanie(database=db, document_models=[Payment, User, Scan])

    yield

    # Cleanup
    client.close()


@pytest.fixture
def mock_stripe_event():
    """Create a mock Stripe subscription created event"""
    return {
        "id": "evt_123",
        "type": "customer.subscription.created",
        "data": {
            "object": {
                "id": "sub_123",
                "customer": "cus_123",
                "status": "active",
                "metadata": {"userId": "1234567890", "type": "pro", "scanId": ""},
            }
        },
    }


@pytest.mark.asyncio
async def test_webhook_signature_verification(mock_stripe_event):
    """Test webhook signature verification"""
    payload = json.dumps(mock_stripe_event).encode()
    sig_header = "t=123,v1=abc"  # Proper Stripe signature format

    # Mock both signature verification and payment check
    with patch("stripe.Webhook.construct_event", return_value=mock_stripe_event), patch.object(
        StripeWebhookHelper.payment_repo,
        "get_by_event_id",
        new_callable=AsyncMock,
        return_value=None,
    ):

        event = await StripeWebhookService.handle_webhook(payload, sig_header)
        assert event["type"] == "customer.subscription.created"
        assert event["id"] == "evt_123"


@pytest.mark.asyncio
async def test_subscription_created_handler(mock_stripe_event):
    """Test subscription created event handling"""

    test_user = await UserRepository.create_test_user("test_user")
    # Mock necessary repository methods and utility functions
    with patch("api.v1.payments.helpers.stripe_webhook.UserRepository") as mock_user_repo, patch(
        "api.v1.payments.helpers.stripe_webhook.PaymentRepository"
    ) as mock_payment_repo, patch(
        "api.v1.payments.helpers.stripe_webhook.ScanRepository"
    ) as mock_scan_repo, patch(
        "api.v1.payments.helpers.stripe_utils.find_user", new_callable=AsyncMock
    ) as mock_find_user, patch(
        "stripe.Subscription.modify", return_value={"id": "sub_123"}
    ) as mock_stripe_modify:

        # Setup mock user to return our test user
        mock_find_user.return_value = test_user

        # Setup mock repositories
        mock_scan_repo.return_value.update_scan_paid_status = AsyncMock()
        mock_payment_repo.update_subscription_payment = AsyncMock()
        mock_user_repo.get_by_subscription_id = AsyncMock(return_value=None)

        # Mock the subscription type check
        mock_subscription_settings = {"pro": {"some": "settings"}}
        with patch(
            "api.v1.payments.helpers.stripe_webhook.SUBSCRIPTION_SETTINGS",
            mock_subscription_settings,
        ):
            # Call the handler
            await StripeWebhookHelper.handle_subscription_created(mock_stripe_event)

            # Verify Stripe metadata was updated
            mock_stripe_modify.assert_called_once_with(
                "sub_123", metadata={"userId": "1234567890", "type": "pro"}
            )

            # Verify user subscription status in database
            updated_user = await User.find_one({"githubId": "1234567890"})
            assert updated_user is not None
            assert updated_user.subscription.isActive is True
            assert updated_user.subscription.stripeSubscriptionId == "sub_123"


@pytest.mark.asyncio
async def test_invoice_payment_handler(mock_stripe_event):
    """Test invoice payment succeeded event handling"""
    # Create a test user
    test_user = await UserRepository.create_test_user("test_user")

    # First create a subscription
    subscription_event = {
        "id": "evt_123",
        "type": "customer.subscription.created",
        "data": {
            "object": {
                "id": "sub_123",
                "customer": "cus_123",
                "status": "active",
                "metadata": {"userId": "1234567890", "type": "pro", "scanId": ""},
            }
        },
    }

    # Then create invoice payment event
    thirty_days_from_now = int(time.time()) + (30 * 24 * 60 * 60)
    invoice_event = {
        "id": "evt_124",
        "type": "invoice.payment_succeeded",
        "data": {
            "object": {
                "id": "in_123",
                "subscription": "sub_123",
                "customer": "cus_123",
                "lines": {"data": [{"period": {"end": thirty_days_from_now}}]},
            }
        },
    }

    # Mock necessary repository methods and utility functions
    with patch("api.v1.payments.helpers.stripe_webhook.UserRepository") as mock_user_repo, patch(
        "api.v1.payments.helpers.stripe_utils.find_user", new_callable=AsyncMock
    ) as mock_find_user, patch(
        "api.v1.payments.helpers.stripe_utils.verify_stripe_subscription", new_callable=AsyncMock
    ) as mock_verify_sub:

        # Setup mock user to return our test user
        mock_find_user.return_value = test_user

        # Setup mock subscription verification
        mock_verify_sub.return_value = type(
            "Subscription", (), {"metadata": {"type": "pro"}, "id": "sub_123"}
        )

        mock_user_repo.get_by_subscription_id = AsyncMock(return_value=None)

        # Mock the subscription type check
        mock_subscription_settings = {
            "pro": {"monthly_credits": 100, "credit_expiry_period": 2592000}
        }  # 30 days in seconds
        with patch(
            "api.v1.payments.helpers.stripe_webhook.SUBSCRIPTION_SETTINGS",
            mock_subscription_settings,
        ):
            # First create the subscription
            await StripeWebhookHelper.handle_subscription_created(subscription_event)

            # Verify initial subscription
            user_after_sub = await User.find_one({"githubId": "1234567890"})
            assert user_after_sub is not None
            assert user_after_sub.subscription.isActive is True
            assert user_after_sub.subscription.stripeSubscriptionId == "sub_123"

            # Then handle the invoice payment
            await StripeWebhookHelper.handle_invoice_payment(invoice_event)

            # Verify subscription was renewed with new expiry
            updated_user = await User.find_one({"githubId": "1234567890"})
            assert updated_user is not None
            assert updated_user.subscription.isActive is True
            assert updated_user.subscription.credits == 5
            assert abs(updated_user.subscription.expiresAt.timestamp() - thirty_days_from_now) < 10


@pytest.mark.asyncio
async def test_subscription_deleted_handler(mock_stripe_event):
    """Test subscription deletion event handling"""
    # Create a test user
    test_user = await UserRepository.create_test_user("test_user")

    # First create a subscription
    subscription_event = {
        "id": "evt_123",
        "type": "customer.subscription.created",
        "data": {
            "object": {
                "id": "sub_123",
                "customer": "cus_123",
                "status": "active",
                "metadata": {"userId": "1234567890", "type": "pro", "scanId": ""},
            }
        },
    }

    # Then create deletion event
    deletion_event = {
        "id": "evt_125",
        "type": "customer.subscription.deleted",
        "data": {
            "object": {
                "id": "sub_123",
                "status": "canceled",
                "metadata": {"userId": "1234567890", "type": "pro"},
            }
        },
    }

    # Mock necessary repository methods and utility functions
    with patch("api.v1.payments.helpers.stripe_webhook.UserRepository") as mock_user_repo, patch(
        "api.v1.payments.helpers.stripe_utils.find_user", new_callable=AsyncMock
    ) as mock_find_user:

        # Setup mock user to return our test user
        mock_find_user.return_value = test_user
        mock_user_repo.get_by_subscription_id = AsyncMock(return_value=None)

        # Mock the subscription type check
        mock_subscription_settings = {"pro": {"monthly_credits": 5}}
        with patch(
            "api.v1.payments.helpers.stripe_webhook.SUBSCRIPTION_SETTINGS",
            mock_subscription_settings,
        ):
            # First create the subscription
            await StripeWebhookHelper.handle_subscription_created(subscription_event)

            # Verify initial subscription
            user_after_sub = await User.find_one({"githubId": "1234567890"})
            assert user_after_sub is not None
            assert user_after_sub.subscription.isActive is True
            assert user_after_sub.subscription.stripeSubscriptionId == "sub_123"

            # Then handle the deletion
            await StripeWebhookHelper.handle_subscription_deleted(deletion_event)

            # Verify subscription was deactivated
            updated_user = await User.find_one({"githubId": "1234567890"})
            assert updated_user is not None
            assert updated_user.subscription.isActive is False
            assert updated_user.subscription.stripeSubscriptionId is None
