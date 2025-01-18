import asyncio
import os
from datetime import datetime, timedelta, timezone

import pytest
import stripe

from config.settings import STRIPE_API_KEY
from core.db.repositories.user import UserRepository
from core.utils import logger

stripe.api_key = STRIPE_API_KEY
STRIPE_PRO_PRICE_ID = os.getenv("STRIPE_PRO_PRICE_ID")


async def create_test_clock(name: str = "AuditAgent test clock"):
    clock = stripe.test_helpers.TestClock.create(
        frozen_time=datetime.now(timezone.utc),
        name=name,
    )
    logger.info(f"Test clock created: {clock}")
    return clock


async def advance_clock(clock_id: str, days: int = 40):
    new_time = int((datetime.now(timezone.utc) + timedelta(days=days)).timestamp())
    logger.info(f"Advancing clock to: {datetime.fromtimestamp(new_time, tz=timezone.utc)}")

    response = stripe.test_helpers.TestClock.advance(clock_id, frozen_time=new_time)
    await wait_for_clock_ready(clock_id)
    return response


async def wait_for_clock_ready(clock_id: str, max_attempts: int = 5):
    for _ in range(max_attempts):
        clock = stripe.test_helpers.TestClock.retrieve(clock_id)
        logger.info(f"Clock status: {clock.status}")
        if clock.status == "ready":
            return True
        await asyncio.sleep(10)
    return False


async def create_customer_with_subscription(user, clock_id, payment_method="pm_card_visa"):
    customer = stripe.Customer.create(
        email=user.email,
        test_clock=clock_id,
        payment_method=payment_method,
        invoice_settings={"default_payment_method": payment_method},
        name=user.name,
    )
    logger.info(f"Customer created: {customer.id}")

    subscription = stripe.Subscription.create(
        customer=customer.id,
        items=[{"price": STRIPE_PRO_PRICE_ID}],
        metadata={"userId": user.githubId, "type": "pro", "scanId": "test_scan_id"},
    )
    logger.info(f"Subscription created: {subscription.id}, status: {subscription.status}")

    return customer, subscription


async def wait_for_subscription_status(subscription_id, desired_status, max_attempts=5, delay=20):
    for _ in range(max_attempts):
        subscription = stripe.Subscription.retrieve(subscription_id)
        logger.info(f"Checking subscription status: {subscription.status}")
        if subscription.status in (
            desired_status if isinstance(desired_status, list) else [desired_status]
        ):
            return subscription
        await asyncio.sleep(delay)
    return None


@pytest.mark.skip(reason="Skip Stripe integration tests")
@pytest.mark.asyncio
async def test_stripe_subscription_cancellation(setup_db):
    """Test subscription cancellation flow"""
    clock = await create_test_clock()
    assert clock.status == "ready"

    user = await UserRepository.create_test_user("stripe_test_user")
    customer, subscription = await create_customer_with_subscription(user, clock.id)

    # Cancel subscription
    cancelled = stripe.Subscription.modify(subscription.id, cancel_at_period_end=True)
    logger.info(f"Subscription after cancellation request: {cancelled}")

    # Verify cancellation state
    updated_sub = stripe.Subscription.retrieve(subscription.id)
    assert updated_sub.cancel_at_period_end is True
    assert updated_sub.status == "active"

    # Forward time to end of period
    await advance_clock(clock.id)

    # Verify final state
    final_sub = await wait_for_subscription_status(subscription.id, "canceled")
    assert final_sub.status == "canceled"

    updated_user = await UserRepository.get_by_github_id(user.githubId)
    assert not updated_user.subscription.isActive


@pytest.mark.skip(reason="Needs docker to be running")
@pytest.mark.asyncio
async def test_stripe_failed_payment(setup_db):
    """Test subscription cancellation due to failed payment"""
    clock = await create_test_clock()
    assert clock.status == "ready"

    user = await UserRepository.create_test_user("stripe_test_user")
    customer, subscription = await create_customer_with_subscription(user, clock.id)

    # Replace with failing payment method
    payment_methods = stripe.PaymentMethod.list(customer=customer.id, type="card")
    for pm in payment_methods.data:
        stripe.PaymentMethod.detach(pm.id)

    failing_payment = stripe.PaymentMethod.create(
        type="card",
        card={"token": "tok_chargeCustomerFail"},
    )
    stripe.PaymentMethod.attach(failing_payment.id, customer=customer.id)
    stripe.Customer.modify(
        customer.id,
        invoice_settings={"default_payment_method": failing_payment.id},
    )

    # Advance time and check for failed payment
    await advance_clock(clock.id)
    final_sub = await wait_for_subscription_status(subscription.id, "canceled")

    assert final_sub.status == "canceled"
    updated_user = await UserRepository.get_by_github_id(user.githubId)
    assert not updated_user.subscription.isActive
