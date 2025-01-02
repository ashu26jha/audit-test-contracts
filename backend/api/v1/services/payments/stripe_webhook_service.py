import json
from datetime import datetime, timezone
from uuid import UUID

import stripe

from api.v1.models.payment import Payment, PaymentStatus, PaymentType
from api.v1.models.user import User
from api.v1.services.scan_history_service import update_scan_paid_status
from common.logger import logger
from config.settings import STRIPE_WEBHOOK_KEY
from config.subscription_settings import SUBSCRIPTION_SETTINGS


class StripeWebhookService:
    # Define the constant at class level
    STRIPE_CUSTOMER_ID_FIELD = "subscription.stripeCustomerId"
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
            if await Payment.find_one({"event_id": event["id"]}):
                logger.info(f"Event {event['id']} already processed, skipping")
                return event

            event_type = event["type"]
            logger.info(f"Processing new Stripe event: {event_type} [{event['id']}]")

            # Handle different event types
            if event_type == "checkout.session.completed":
                session = event["data"]["object"]
                if session.get("mode") == "subscription":
                    await StripeWebhookService.handle_subscription_completed(event)
                else:
                    await StripeWebhookService.handle_checkout_completed(event)
            elif event_type == "customer.subscription.created":
                await StripeWebhookService.handle_subscription_created(event)
            elif event_type == "invoice.payment_succeeded":
                await StripeWebhookService.handle_invoice_payment(event)
            elif event_type == "customer.subscription.updated":
                await StripeWebhookService.handle_subscription_updated(event)
            elif event_type == "customer.subscription.deleted":
                await StripeWebhookService.handle_subscription_deleted(event)
            elif event_type in StripeWebhookService.IGNORABLE_EVENTS:
                logger.debug(f"Ignoring known event type: {event_type}")
            else:
                logger.warning(f"Received unhandled Stripe event type: {event_type}")

            return event

        except json.JSONDecodeError:
            logger.error("Invalid payload received")
            raise ValueError("Invalid payload")
        except stripe.error.SignatureVerificationError as e:
            logger.error(f"Invalid signature: {str(e)}")
            raise ValueError("Invalid signature")
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

            payment = await Payment.find_one({"stripeSessionId": session_id})
            if not payment:
                logger.error(f"Payment not found for session ID: {session_id}")
                return

            if paid_status == "paid" and payment.status != PaymentStatus.COMPLETED:
                payment.status = PaymentStatus.COMPLETED
                payment.event_id = event["id"]
                payment.amount = session["amount_total"] / 100
                payment.currency = session["currency"]
                payment.updatedAt = datetime.now(timezone.utc)
                await payment.save()

                # Handle free scans (0 or 1 finding) or paid scans
                is_free = session["amount_total"] == 0
                await update_scan_paid_status(payment.scan_id, True, is_free)
                logger.info(f"Payment completed for session ID: {session_id}. Free scan: {is_free}")
            elif paid_status == "unpaid":
                payment.status = PaymentStatus.FAILED
                payment.payment_type = PaymentType.FAILED  # Only update type for failed payments
                payment.updatedAt = datetime.now(timezone.utc)
                await payment.save()
                logger.info(f"Payment marked as failed for session ID: {session_id}")

        except Exception as e:
            logger.error(f"Error processing payment webhook: {str(e)}")
            raise

    @staticmethod
    async def handle_invoice_payment(event: dict):
        """Handle recurring subscription payments"""
        try:
            invoice = event["data"]["object"]
            subscription_id = invoice.get("subscription")
            customer_id = invoice.get("customer")

            if not subscription_id:
                logger.error("No subscription ID in invoice")
                return

            # Try to get user from subscription metadata first
            subscription = stripe.Subscription.retrieve(subscription_id)
            user_id = subscription.metadata.get("userId")

            if not user_id and customer_id:
                # Fallback to customer ID lookup
                user = await User.find_one(
                    {StripeWebhookService.STRIPE_CUSTOMER_ID_FIELD: customer_id}
                )
                if user:
                    user_id = user.githubId
                    # Update subscription metadata for future events
                    stripe.Subscription.modify(subscription_id, metadata={"userId": user_id})

            if not user_id:
                logger.error(f"User not found for customer {customer_id}")
                return

            # Find user and update their subscription
            user = await User.by_github_id(user_id)
            if user:
                # Renew subscription credits and update dates
                user.subscription.lastRenewalAt = datetime.now(timezone.utc)
                # Use 31 days as default expiry period
                user.subscription.expiresAt = (
                    datetime.now(timezone.utc)
                    + SUBSCRIPTION_SETTINGS["pro"]["credit_expiry_period"]
                )
                user.subscription.credits = SUBSCRIPTION_SETTINGS["pro"]["monthly_credits"]
                user.subscription.monthlyCredits = SUBSCRIPTION_SETTINGS["pro"]["monthly_credits"]
                await user.save()
                logger.info(f"Subscription renewed for user {user.githubId}")
            else:
                logger.error(f"User not found for ID {user_id}")

        except Exception as e:
            logger.error(f"Error handling invoice payment: {str(e)}")
            raise

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

            if not user_id and customer_id:
                # Try to find user by customer ID if metadata is missing
                user = await User.find_one(
                    {StripeWebhookService.STRIPE_CUSTOMER_ID_FIELD: customer_id}
                )
                if user:
                    user_id = user.githubId

            if not user_id:
                logger.error(StripeWebhookService.NO_USER_FOUND_ERROR)
                return

            # Update subscription metadata to ensure it's available for future events
            if subscription_id:
                try:
                    stripe.Subscription.modify(
                        subscription_id, metadata={"userId": user_id, "scanId": scan_id}
                    )
                except Exception as e:
                    logger.error(f"Error updating subscription metadata: {str(e)}")

                # Activate the subscription immediately
                await StripeWebhookService.activate_subscription(user_id, subscription_id)

            logger.info(f"Subscription checkout completed for user {user_id}")

        except Exception as e:
            logger.error(f"Error processing subscription completion: {str(e)}")
            raise

    @staticmethod
    async def handle_subscription_created(event: dict):
        """Handle new subscription creation"""
        try:
            subscription = event["data"]["object"]
            metadata = subscription.get("metadata", {})
            user_id = metadata.get("userId")
            customer_id = subscription.get("customer")
            subscription_id = subscription["id"]

            if not user_id and customer_id:
                # Try to find user by customer ID if metadata is missing
                user = await User.find_one(
                    {StripeWebhookService.STRIPE_CUSTOMER_ID_FIELD: customer_id}
                )
                if user:
                    user_id = user.githubId
                    # Update subscription metadata if missing
                    stripe.Subscription.modify(subscription_id, metadata={"userId": user_id})

            if not user_id:
                logger.error(StripeWebhookService.NO_USER_FOUND_ERROR)
                return

            # Activate the subscription
            await StripeWebhookService.activate_subscription(user_id, subscription_id)
            logger.info(f"Subscription created for user {user_id}")

        except Exception as e:
            logger.error(f"Error handling subscription creation: {str(e)}")
            raise

    @staticmethod
    async def handle_subscription_deleted(event: dict):
        """Handle subscription cancellation/deletion"""
        try:
            subscription = event["data"]["object"]
            metadata = subscription.get("metadata", {})
            user_id = metadata.get("userId")

            if not user_id:
                logger.error("No userId in subscription metadata")
                return

            await StripeWebhookService.deactivate_subscription(user_id)
            logger.info(f"Subscription deleted for user {user_id}")

        except Exception as e:
            logger.error(f"Error handling subscription deletion: {str(e)}")
            raise

    @staticmethod
    async def activate_subscription(user_id: str, subscription_id: str):
        """Activate user subscription and set up initial state"""
        user = await User.by_github_id(user_id)
        if user:
            # Create or get Stripe customer
            if not user.subscription.stripeCustomerId:
                customer = stripe.Customer.create(
                    email=user.email, metadata={"githubId": user.githubId}
                )
                user.subscription.stripeCustomerId = customer.id

            user.subscription.isActive = True
            user.subscription.type = "pro"
            user.subscription.credits = SUBSCRIPTION_SETTINGS["pro"]["monthly_credits"]
            user.subscription.monthlyCredits = SUBSCRIPTION_SETTINGS["pro"]["monthly_credits"]
            user.subscription.stripeSubscriptionId = subscription_id
            user.subscription.expiresAt = (
                datetime.now(timezone.utc) + SUBSCRIPTION_SETTINGS["pro"]["credit_expiry_period"]
            )
            user.subscription.lastRenewalAt = datetime.now(timezone.utc)
            await user.save()
            logger.info(f"Subscription activated for user {user_id}")

    @staticmethod
    async def deactivate_subscription(user_id: str):
        """Deactivate subscription but keep credits until expiry"""
        user = await User.by_github_id(user_id)
        if user:
            user.subscription.isActive = False
            await user.save()
            logger.info(f"Subscription deactivated for user {user_id}")

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

            if not user_id:
                logger.error(StripeWebhookService.NO_USER_FOUND_ERROR)
                return

            user = await User.by_github_id(user_id)
            if not user:
                logger.error(f"User not found for subscription update: {user_id}")
                return

            # Handle different subscription statuses
            if status == "past_due":
                # Payment failed but subscription still active
                logger.warning(f"Subscription payment past due for user {user_id}")
            elif status == "unpaid":
                # Payment failed and subscription needs action
                user.subscription.isActive = False
                await user.save()
                logger.warning(f"Subscription marked unpaid for user {user_id}")
            elif status == "active":
                # Subscription back to active (e.g., after past_due payment)
                # Update all subscription details
                user.subscription.isActive = True
                user.subscription.type = "pro"
                user.subscription.stripeSubscriptionId = subscription_id
                user.subscription.credits = SUBSCRIPTION_SETTINGS["pro"]["monthly_credits"]
                user.subscription.monthlyCredits = SUBSCRIPTION_SETTINGS["pro"]["monthly_credits"]
                user.subscription.expiresAt = (
                    datetime.now(timezone.utc)
                    + SUBSCRIPTION_SETTINGS["pro"]["credit_expiry_period"]
                )
                await user.save()
                logger.info(f"Subscription reactivated for user {user_id}")

                # Update scan status as paid (Limited scan is free when subscribing, no credit deducted)
                if scan_id:
                    try:
                        await update_scan_paid_status(UUID(scan_id), True, True)
                        logger.info(f"Marked scan {scan_id} as paid for subscription checkout")
                        # Update payment type to subscription
                        payment = await Payment.find_one(Payment.scan_id == UUID(scan_id))
                        if payment:
                            payment.payment_type = PaymentType.SUBSCRIPTION
                            payment.status = PaymentStatus.COMPLETED
                            payment.updatedAt = datetime.now(timezone.utc)
                            await payment.save()
                        logger.info(f"Marked scan {scan_id} as subscription payment")
                    except Exception as e:
                        logger.error(f"Error marking scan as paid: {str(e)}")

            logger.info(f"Subscription updated for user {user_id} - Status: {status}")

        except Exception as e:
            logger.error(f"Error handling subscription update: {str(e)}")
            raise
