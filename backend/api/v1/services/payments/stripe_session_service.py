from uuid import UUID

import stripe
from api.v1.models.payment import Payment
from api.v1.models.scan import Scan
from api.v1.models.user import User
from bson import ObjectId
from common.logger import logger
from config.settings import FRONTEND_URL, STRIPE_API_KEY
from fastapi import HTTPException

stripe.api_key = STRIPE_API_KEY
if not STRIPE_API_KEY:
    message = "Stripe API key is not set"
    logger.error(message)
    raise HTTPException(status_code=500, detail="Internal server error")


class StripeSessionService:
    @staticmethod
    async def create_checkout_session(scan_id: str):
        scan = await Scan.find_one(Scan.scan_id == UUID(scan_id))
        if not scan:
            message = f"No scan found with ID: {scan_id}"
            logger.error(message)
            raise HTTPException(status_code=404, detail=message)

        user_id = str(scan.user_id)

        user = await User.find_one(User.id == ObjectId(user_id))
        if not user:
            message = f"No user found with ID: {user_id}"
            logger.error(message)
            raise HTTPException(status_code=404, detail=message)

        user_email = user.email

        checkout_session = stripe.checkout.Session.create(
            billing_address_collection="auto",
            customer_email=user_email,
            line_items=[
                {
                    "price_data": {
                        "currency": "usd",
                        "product_data": {"name": "Payment for Audit Agent full report."},
                        "unit_amount": 2000,
                    },
                    "quantity": 1,
                }
            ],
            mode="payment",
            success_url=f"{FRONTEND_URL}/payment-result?session_id={{CHECKOUT_SESSION_ID}}&status=success",
            cancel_url=f"{FRONTEND_URL}/payment-result?session_id={{CHECKOUT_SESSION_ID}}&status=error",
            metadata={
                "userId": str(user_id),
                "scanId": scan_id,
            },
        )

        # Store the session ID
        await StripeSessionService.store_session_id(scan_id, checkout_session.id, user_id)

        return checkout_session

    @staticmethod
    async def store_session_id(scan_id: str, session_id: str, user_id: str):
        payment = Payment(
            event_id="",
            user_id=user_id,
            scan_id=scan_id,
            amount=0,
            currency="usd",
            status="pending",
            stripeSessionId=session_id,
        )
        await payment.create()

    @staticmethod
    async def verify_session_id(session_id: str) -> bool:
        payment = await Payment.find_one(Payment.stripeSessionId == session_id)
        return payment is not None

    @staticmethod
    async def retrieve_session(session_id: str):
        return stripe.checkout.Session.retrieve(session_id)
