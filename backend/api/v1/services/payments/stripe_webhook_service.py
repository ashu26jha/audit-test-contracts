import json
from datetime import datetime, timezone

import stripe

from api.v1.models.payment import Payment, PaymentStatus
from api.v1.services.scan_history_service import update_scan_paid_status
from common.logger import logger
from config.settings import STRIPE_WEBHOOK_KEY


class StripeWebhookService:
    @staticmethod
    async def handle_webhook(payload: bytes, sig_header: str):
        try:
            event = stripe.Webhook.construct_event(payload, sig_header, STRIPE_WEBHOOK_KEY)
            return event
        except json.JSONDecodeError:
            raise ValueError("Invalid payload")
        except stripe.error.SignatureVerificationError:
            raise stripe.error.SignatureVerificationError("Invalid signature")

    @staticmethod
    async def update_payment_status(event: dict):
        session = event["data"]["object"]
        paid_status = session["payment_status"]
        session_id = session["id"]

        payment = await Payment.find_one(Payment.stripeSessionId == session_id)
        if payment:
            if paid_status == "paid" and payment.status != PaymentStatus.COMPLETED:
                payment.status = PaymentStatus.COMPLETED
                payment.event_id = event["id"]
                payment.amount = session["amount_total"] / 100
                payment.currency = session["currency"]
                payment.updatedAt = datetime.now(timezone.utc)
                await payment.save()

                await update_scan_paid_status(payment.scan_id, True)
                logger.info(f"Payment marked as completed for session ID: {session_id}")
            elif paid_status == "unpaid":
                payment.status = PaymentStatus.FAILED
                payment.updatedAt = datetime.now(timezone.utc)
                await payment.save()
                logger.info(f"Payment marked as failed for session ID: {session_id}")
            else:
                logger.info(f"Payment status unchanged for session ID: {session_id}")
        else:
            logger.error(f"Payment not found for session ID: {session_id}")
