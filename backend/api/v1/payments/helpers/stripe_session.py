from uuid import UUID

import stripe

from api.v1.payments.helpers.get_result_url import get_payment_urls
from config.subscription_settings import SUBSCRIPTION_SETTINGS
from core.db.repositories.payment import PaymentRepository
from core.models.user import User
from core.utils.validate import validate_user_scan_access

payment_repo = PaymentRepository()


@staticmethod
async def stripe_checkout_session(user: User, scan_id: str):
    # 1. Check if the scan exists and belongs to the user
    await validate_user_scan_access(UUID(scan_id), user)

    # 2. Get user ID and email
    user_id = user.githubId
    user_email = user.email
    unit_amount = SUBSCRIPTION_SETTINGS["single"]["price"]

    # 3. Get payment URLs
    success_url, cancel_url = get_payment_urls(scan_id)

    # 4. Create Stripe checkout session
    checkout_session = stripe.checkout.Session.create(
        billing_address_collection="auto",
        customer_email=user_email,
        line_items=[
            {
                "price_data": {
                    "currency": "usd",
                    "product_data": {"name": "Payment for AuditAgent full report."},
                    "unit_amount": unit_amount,
                },
                "quantity": 1,
            }
        ],
        mode="payment",
        allow_promotion_codes=True,
        success_url=success_url,
        cancel_url=cancel_url,
        metadata={"userId": user_id, "scanId": scan_id, "type": "one_time"},
    )

    # 5. Update Payment entry in DB
    await payment_repo.update_success_payment(
        scan_id=UUID(scan_id),
        session_id=checkout_session.id,
        user_id=user_id,
        amount=unit_amount / 100,  # Convert cents to dollars
    )

    return checkout_session
