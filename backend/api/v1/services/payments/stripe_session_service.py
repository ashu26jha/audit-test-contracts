from uuid import UUID

import stripe
from fastapi import HTTPException

from api.v1.models.payment import Payment
from api.v1.models.user import User
from common.logger import logger
from common.validate import validate_user_scan_access
from config.settings import FRONTEND_URL, STRIPE_API_KEY

stripe.api_key = STRIPE_API_KEY
if not STRIPE_API_KEY:
    message = "Stripe API key is not set"
    logger.error(message)
    raise HTTPException(status_code=500, detail="Internal server error")


class StripeSessionService:
    @staticmethod
    async def create_checkout_session(user: User, scan_id: str):
        # Check if the scan exists and belongs to the user
        await validate_user_scan_access(UUID(scan_id), user)

        user_id = str(user.id)
        user_email = user.email
        unit_amount = 2000  # $20.00

        checkout_session = stripe.checkout.Session.create(
            billing_address_collection="auto",
            customer_email=user_email,
            line_items=[
                {
                    "price_data": {
                        "currency": "usd",
                        "product_data": {"name": "Payment for Audit Agent full report."},
                        "unit_amount": unit_amount,
                    },
                    "quantity": 1,
                }
            ],
            mode="payment",
            allow_promotion_codes=True,
            success_url=f"{FRONTEND_URL}/payment-result?session_id={{CHECKOUT_SESSION_ID}}&status=success&scan_id={scan_id}",
            cancel_url=f"{FRONTEND_URL}/payment-result?session_id={{CHECKOUT_SESSION_ID}}&status=error&scan_id={scan_id}",
            metadata={
                "userId": str(user_id),
                "scanId": scan_id,
            },
        )

        # Store the session ID
        await StripeSessionService.store_session_id(
            scan_id, checkout_session.id, user_id, unit_amount
        )

        return checkout_session

    @staticmethod
    async def store_session_id(scan_id: str, session_id: str, user_id: str, amount: int):
        payment = Payment(
            event_id="",
            user_id=user_id,
            scan_id=scan_id,
            amount=amount / 100,  # Convert cents to dollars
            currency="usd",
            status="pending",
            stripeSessionId=session_id,
        )
        await payment.create()
