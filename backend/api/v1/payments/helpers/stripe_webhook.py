import json
from uuid import UUID

import stripe

from api.v1.payments.helpers.subscription_helper import (
    activate_subscription,
    deactivate_subscription,
)
from config.settings import STRIPE_WEBHOOK_KEY
from core.db.repositories.payment import PaymentRepository
from core.db.repositories.scan import ScanRepository
from core.db.repositories.user import UserRepository
from core.models.payment import PaymentStatus
from core.utils.logger import logger


class StripeWebhookHelper:
    payment_repo = PaymentRepository()
    user_repo = UserRepository()
    scan_repo = ScanRepository()

    NO_USER_FOUND_ERROR = "No userId in subscription metadata or customer not found"

    # Events that we can safely ignore
    IGNORABLE_EVENTS = {
        "promotion_code.updated",
        "customer.discount.created",
        "customer.discount.deleted",
        "payment_intent.created",
        "payment_intent.succeeded",
    }

    @staticmethod
    async def handle_webhook(payload: bytes, sig_header: str):
        """Main webhook handler that validates and routes events."""
        try:
            event = stripe.Webhook.construct_event(payload, sig_header, STRIPE_WEBHOOK_KEY)

            # Check if we've already processed this event by looking for a payment with this event_id
            payment = await StripeWebhookHelper.payment_repo.get_by_event_id(event["id"])
            if payment:
                logger.info(f"Event {event['id']} already processed, skipping")
                return event

            event_type = event["type"]
            logger.info(f"Processing new Stripe event: {event_type} [{event['id']}]")

            # Handle different event types
            if event_type == "checkout.session.completed":
                session = event["data"]["object"]
                if session.get("mode") == "subscription":
                    await StripeWebhookHelper.handle_subscription_completed(event)
                else:
                    await StripeWebhookHelper.handle_checkout_completed(event)
            elif event_type == "customer.subscription.created":
                await StripeWebhookHelper.handle_subscription_created(event)
            elif event_type == "invoice.payment_succeeded":
                await StripeWebhookHelper.handle_invoice_payment(event)
            elif event_type == "customer.subscription.updated":
                await StripeWebhookHelper.handle_subscription_updated(event)
            elif event_type == "customer.subscription.deleted":
                await StripeWebhookHelper.handle_subscription_deleted(event)
            elif event_type in StripeWebhookHelper.IGNORABLE_EVENTS:
                logger.debug(f"Ignoring known event type: {event_type}")
            else:
                logger.warning(f"Received unhandled Stripe event type: {event_type}")

            return event

        except json.JSONDecodeError as e:
            logger.error("Invalid payload received")
            raise ValueError("Invalid payload") from e
        except stripe.error.SignatureVerificationError as e:
            logger.error("Invalid Stripe signature")
            raise ValueError("Invalid signature") from e
        except Exception as e:
            logger.error(f"Error processing webhook: {str(e)}")
            raise

    @staticmethod
    async def handle_checkout_completed(event: dict):
        """Handle one-time payment completion"""
        try:
            session = event["data"]["object"]
            paid_status = session["payment_status"]
            session_id = session["id"]

            # Check if we've already processed this payment
            payment = await StripeWebhookHelper.payment_repo.get_by_session_id(session_id)
            if not payment:
                logger.error(f"Payment not found for session ID: {session_id}")
                return

            # Skip if payment is already completed
            if payment.status == PaymentStatus.COMPLETED:
                logger.info(f"Payment already completed for session ID: {session_id}")
                return

            if paid_status == "paid":
                await StripeWebhookHelper.payment_repo.update_success_payment(
                    scan_id=payment.scan_id,
                    user_id=payment.user_id,
                    session_id=session_id,
                    amount=session["amount_total"] / 100,
                    event_id=event["id"],
                )

                # Handle free scans (0 or 1 finding) or paid scans
                is_free = session["amount_total"] == 0
                await StripeWebhookHelper.scan_repo.update_scan_paid_status(
                    payment.scan_id, True, is_free
                )
                logger.info(f"Payment completed for session ID: {session_id}. Free scan: {is_free}")

            elif paid_status == "unpaid":
                await StripeWebhookHelper.payment_repo.update_failed_payment(
                    payment.scan_id,
                    payment.user_id,
                    event_id=event["id"],
                )
                logger.info(f"Payment marked as failed for session ID: {session_id}")

        except Exception as e:
            logger.error(f"Error handling checkout completion: {str(e)}")

    @staticmethod
    async def handle_invoice_payment(event: dict):
        """Handle recurring subscription payments"""
        invoice = event["data"]["object"]
        subscription_id = invoice.get("subscription")
        customer_id = invoice.get("customer")

        if not subscription_id:
            logger.error("No subscription ID in invoice")
            return

        try:
            # Try to get user from subscription metadata first
            subscription = stripe.Subscription.retrieve(subscription_id)
            user_id = subscription.metadata.get("userId")

            if not user_id and customer_id:
                # Fallback to customer ID lookup
                user = await UserRepository.get_by_customer_id(customer_id)
                if user:
                    user_id = user.githubId
                    # Update subscription metadata for future events
                    try:
                        stripe.Subscription.modify(subscription_id, metadata={"userId": user_id})
                    except stripe.error.StripeError as e:
                        logger.error(f"Error updating subscription metadata: {str(e)}")

            if not user_id:
                logger.error(f"User not found for customer {customer_id}")
                return

            # Find user and renew their subscription credits
            user = await UserRepository.get_by_github_id(user_id)
            if user:
                await UserRepository.renew_subscription_credits(user)
                logger.info(f"Subscription renewed for user {user.githubId}")
            else:
                logger.error(f"User not found for ID {user_id}")

        except stripe.error.StripeError as e:
            logger.error(f"Stripe error in invoice payment: {str(e)}")
        except Exception as e:
            logger.error(f"Error handling invoice payment: {str(e)}")

    @staticmethod
    async def handle_subscription_completed(event: dict):
        """Handle subscription checkout completion"""
        try:
            session = event["data"]["object"]
            metadata = session.get("metadata", {})
            user_id = metadata.get("userId")
            scan_id = metadata.get("scanId")
            customer_id = session.get("customer")
            subscription_id = session.get("subscription")

            if not subscription_id:
                logger.error("No subscription ID in checkout session")
                return

            # Try to find user from metadata or customer ID
            if not user_id and customer_id:
                user = await UserRepository.get_by_customer_id(customer_id)
                if user:
                    user_id = user.githubId

            if not user_id:
                logger.error(StripeWebhookHelper.NO_USER_FOUND_ERROR)
                return

            # Update subscription metadata to ensure it's available for future events
            try:
                stripe.Subscription.modify(
                    subscription_id, metadata={"userId": user_id, "scanId": scan_id or ""}
                )
            except Exception as e:
                logger.error(f"Error updating subscription metadata: {str(e)}")

            # Activate the subscription immediately
            await activate_subscription(user_id, subscription_id)
            logger.info(f"Subscription checkout completed for user {user_id}")

        except Exception as e:
            logger.error(f"Error handling subscription completion: {str(e)}")

    @staticmethod
    async def handle_subscription_created(event: dict):
        """Handle new subscription creation"""
        try:
            subscription = event["data"]["object"]
            metadata = subscription.get("metadata", {})
            user_id = metadata.get("userId")
            customer_id = subscription.get("customer")
            subscription_id = subscription["id"]

            # Skip if we've already processed this subscription
            user = await UserRepository.get_by_subscription_id(subscription_id)
            if user:
                logger.info(f"Subscription {subscription_id} already processed")
                return

            # Try to find user from metadata or customer ID
            if not user_id and customer_id:
                user = await UserRepository.get_by_customer_id(customer_id)
                if user:
                    user_id = user.githubId
                    try:
                        stripe.Subscription.modify(subscription_id, metadata={"userId": user_id})
                    except stripe.error.StripeError as e:
                        logger.error(f"Error updating subscription metadata: {str(e)}")

            if not user_id:
                logger.error(StripeWebhookHelper.NO_USER_FOUND_ERROR)
                return

            await activate_subscription(user_id, subscription_id)
            logger.info(f"Subscription created for user {user_id}")

        except Exception as e:
            logger.error(f"Error handling subscription creation: {str(e)}")

    @staticmethod
    async def handle_subscription_deleted(event: dict):
        """Handle subscription cancellation/deletion"""
        subscription = event["data"]["object"]
        metadata = subscription.get("metadata", {})
        user_id = metadata.get("userId")

        if not user_id:
            logger.error("No userId in subscription metadata")
            return

        await deactivate_subscription(user_id)
        logger.info(f"Subscription deleted for user {user_id}")

    @staticmethod
    async def handle_subscription_updated(event: dict):
        """Handle subscription updates (status changes, plan changes, etc.)"""
        try:
            subscription = event["data"]["object"]
            metadata = subscription.get("metadata", {})
            user_id = metadata.get("userId")
            status = subscription.get("status")
            scan_id = metadata.get("scanId")
            subscription_id = subscription["id"]

            valid_statuses = [
                "active",
                "past_due",
                "unpaid",
                "canceled",
                "incomplete",
                "incomplete_expired",
            ]
            if status not in valid_statuses:
                logger.warning(f"Unexpected subscription status: {status}")
                return

            # Try to find user from metadata or subscription ID
            if not user_id:
                user = await UserRepository.get_by_subscription_id(subscription_id)
                if user:
                    user_id = user.githubId
                    try:
                        stripe.Subscription.modify(subscription_id, metadata={"userId": user_id})
                    except stripe.error.StripeError as e:
                        logger.error(f"Error updating subscription metadata: {str(e)}")

            if not user_id:
                logger.error(StripeWebhookHelper.NO_USER_FOUND_ERROR)
                return

            user = await UserRepository.get_by_github_id(user_id)
            if not user:
                logger.error(f"User not found for subscription update: {user_id}")
                return

            # Handle different subscription statuses
            if status == "past_due":
                logger.warning(f"Subscription payment past due for user {user_id}")
            elif status == "unpaid":
                await UserRepository.deactivate_subscription(user)
                logger.warning(f"Subscription marked unpaid for user {user_id}")
            elif status == "active":
                # Activate or reactivate subscription
                await UserRepository.activate_subscription(
                    user,
                    subscription_id=subscription_id,
                    customer_id=user.subscription.stripeCustomerId,
                )
                logger.info(f"Subscription reactivated for user {user_id}")

                # Update scan status if this was from a checkout
                if scan_id:
                    try:
                        await StripeWebhookHelper.scan_repo.update_scan_paid_status(
                            UUID(scan_id), True, True
                        )
                        logger.info(f"Marked scan {scan_id} as paid for subscription checkout")
                        # Update payment type to subscription
                        await PaymentRepository.update_subscription_payment(UUID(scan_id), user_id)
                        logger.info(f"Marked scan {scan_id} as subscription payment")
                    except Exception as e:
                        logger.error(f"Error updating scan/payment status: {str(e)}")

            logger.info(f"Subscription updated for user {user_id} - Status: {status}")

        except Exception as e:
            logger.error(f"Error handling subscription update: {str(e)}")
