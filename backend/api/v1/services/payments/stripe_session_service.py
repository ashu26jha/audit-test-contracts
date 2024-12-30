from typing import Optional
from uuid import UUID

import stripe
from fastapi import HTTPException

from api.v1.models.payment import Payment
from api.v1.models.user import User
from common.logger import logger
from common.validate import validate_user_scan_access
from config.settings import FRONTEND_URL, STRIPE_API_KEY
from config.subscription_settings import SUBSCRIPTION_SETTINGS

# Constants for URLs and common values
PAYMENT_RESULT_BASE_URL = f"{FRONTEND_URL}/payment-result"
PAYMENT_RESULT_URL = (
    f"{PAYMENT_RESULT_BASE_URL}"
    f"?session_id={{CHECKOUT_SESSION_ID}}"
    f"&status={{status}}"
    f"&scan_id={{scan_id}}"
)

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

        user_id = user.githubId
        user_email = user.email
        unit_amount = SUBSCRIPTION_SETTINGS["single"]["price"]

        success_url, cancel_url = StripeSessionService._get_payment_urls(scan_id)

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

        # Store the session ID
        await StripeSessionService._store_session_id(
            scan_id, checkout_session.id, user_id, unit_amount
        )

        return checkout_session

    @staticmethod
    async def create_subscription_session(user: User, scan_id: Optional[str] = None):
        """Create subscription session for pro plan."""
        # Check if the scan exists and belongs to the user
        if scan_id:
            await validate_user_scan_access(UUID(scan_id), user)

        if not SUBSCRIPTION_SETTINGS["pro"]["price"]:
            raise HTTPException(
                status_code=500, detail="Stripe subscription price ID is not configured"
            )

        user_id = user.githubId
        user_email = user.email

        success_url, cancel_url = StripeSessionService._get_payment_urls(scan_id or "")

        try:
            checkout_session = stripe.checkout.Session.create(
                billing_address_collection="auto",
                customer_email=user_email,
                line_items=[
                    {
                        "price": SUBSCRIPTION_SETTINGS["pro"]["price"],
                        "quantity": 1,
                    }
                ],
                mode="subscription",
                payment_method_collection="if_required",
                allow_promotion_codes=True,
                success_url=success_url,
                cancel_url=cancel_url,
                metadata={"userId": user_id, "scanId": scan_id or "", "type": "subscription"},
            )
            return checkout_session
        except stripe.error.StripeError as e:
            logger.error(f"Stripe error creating subscription session: {str(e)}")
            raise HTTPException(status_code=400, detail=str(e))
        except Exception as e:
            logger.error(f"Error creating subscription session: {str(e)}")
            raise HTTPException(status_code=500, detail="Failed to create subscription session")

    @staticmethod
    def _get_payment_urls(scan_id: str) -> tuple[str, str]:
        """Helper method to generate success and cancel URLs."""
        success_url = PAYMENT_RESULT_URL.format(
            CHECKOUT_SESSION_ID="{CHECKOUT_SESSION_ID}", status="success", scan_id=scan_id
        )
        cancel_url = PAYMENT_RESULT_URL.format(
            CHECKOUT_SESSION_ID="{CHECKOUT_SESSION_ID}", status="error", scan_id=scan_id
        )
        return success_url, cancel_url

    @staticmethod
    async def _store_session_id(scan_id: str, session_id: str, user_id: str, amount: int):
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
