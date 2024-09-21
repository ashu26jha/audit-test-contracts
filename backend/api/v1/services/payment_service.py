import json
from uuid import UUID

import api.v1.models.payment as Payment
import stripe
from api.v1.models.scan import Scan
from api.v1.models.user import User
from bson import ObjectId
from config.settings import STRIPE_API_KEY, STRIPE_WEBHOOK_KEY

stripe.api_key = STRIPE_API_KEY


class PaymentService:
    @staticmethod
    async def create_checkout_session(scan_id: str):

        # Retrieve `user_id` from `scan_id`
        scan = await Scan.find_one(Scan.scan_id == UUID(scan_id))
        if not scan:
            raise ValueError(f"No scan found with ID: {scan_id}")
        user_id = ObjectId(scan.user_id)

        # Retrieve `email` for the `user_id`
        user = await User.find_one(User.id == user_id)
        if not user:
            raise ValueError(f"No user found with ID: {user_id}")
        user_email = user.email

        checkout_session = stripe.checkout.Session.create(
            billing_address_collection="auto",
            customer_email=user_email,
            line_items=[
                {
                    "price_data": {
                        "currency": "usd",
                        "product_data": {"name": "Payment for scan"},
                        "unit_amount": 120,
                    },
                    "quantity": 1,
                }
            ],
            mode="payment",
            success_url="http://0.0.0.0:8000/api/v1/payments/payment_success?session_id={CHECKOUT_SESSION_ID}",
            metadata={
                "userId": str(user_id),
                "scanId": scan_id,
            },
        )
        return checkout_session

    @staticmethod
    async def handle_webhook(payload: bytes, sig_header: str):
        try:
            event = stripe.Webhook.construct_event(payload, sig_header, STRIPE_WEBHOOK_KEY)
        except json.JSONDecodeError:
            raise ValueError("Invalid payload")
        except stripe.error.SignatureVerificationError:
            raise ValueError("Invalid signature")

        if event["type"] == "checkout.session.completed":
            event_id = event["id"]

            try:
                existing_payment = await Payment.Payment.find_one(
                    Payment.Payment.event_id == event_id
                )

                if existing_payment:
                    return True

                if event["data"]:
                    object_received = event["data"]["object"]
                    session_id = object_received["id"]
                    user_id = object_received["metadata"]["userId"]
                    scan_id = object_received["metadata"]["scanId"]
                    amount = object_received["amount_total"]
                    currency = object_received["currency"]

                    new_payment = Payment.Payment(
                        event_id=event_id,
                        user_id=user_id,
                        scan_id=scan_id,
                        amount=amount,
                        currency=currency,
                        status="completed",
                        stripeSessionId=session_id,
                    )

                    await new_payment.create()

                    # Update the scan to mark it as paid
                    scan = await Scan.find_one(Scan.scan_id == UUID(scan_id))
                    scan.paid_status = True
                    await scan.save()

            except Exception:
                return False

        return True
