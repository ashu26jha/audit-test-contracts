import json
from uuid import UUID

import stripe

from api.v1.payments.helpers.stripe_utils import (
    find_user,
    sync_stripe_metadata,
    verify_stripe_subscription,
)
from api.v1.payments.helpers.subscription_helper import (
    activate_subscription,
    deactivate_subscription,
)
from config.settings import STRIPE_WEBHOOK_KEY
from config.subscription_settings import SUBSCRIPTION_SETTINGS
from core.db.repositories.payment import PaymentRepository
from core.db.repositories.scan import ScanRepository
from core.db.repositories.user import UserRepository
from core.utils.logger import logger


class StripeWebhookHelper:
    payment_repo = PaymentRepository()
    user_repo = UserRepository()
    scan_repo = ScanRepository()

    ERROR_MESSAGES = {
        "NO_USER": "No userId in subscription metadata or customer not found",
        "NO_SUBSCRIPTION": "No subscription ID found in event data",
        "NO_TYPE": "No subscription type found in metadata",
        "INVALID_STATUS": "Invalid subscription status received",
        "INVALID_CUSTOMER": "Invalid customer ID provided",
        "MISSING_DATA": "Missing required data in event",
    }

    # Events that we can safely ignore
    IGNORABLE_EVENTS = {
        "checkout.session.completed",
        "promotion_code.updated",
        "customer.discount.created",
        "customer.discount.deleted",
        "payment_intent.created",
        "payment_intent.succeeded",
        "payment_method.attached",
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
            if event_type == "customer.subscription.created":
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
    async def handle_subscription_created(event: dict):
        """Handle new subscription creation"""
        try:
            subscription = event["data"]["object"]
            metadata = subscription.get("metadata", {})
            user_id = metadata.get("userId")
            customer_id = subscription.get("customer")
            subscription_id = subscription["id"]
            subscription_type = metadata.get("type")
            scan_id = metadata.get("scanId")

            # Validate subscription type
            if subscription_type not in SUBSCRIPTION_SETTINGS:
                logger.error(f"Invalid subscription type: {subscription_type}")
                return
            # Check if we already have this subscription
            existing_subscription = await UserRepository.get_by_subscription_id(subscription_id)
            if existing_subscription:
                logger.info(f"Subscription {subscription_id} already processed")
                return
            # Find user using utility function
            user = await find_user(
                customer_id=customer_id, subscription_id=subscription_id, user_id=user_id
            )
            if not user:
                logger.error(StripeWebhookHelper.ERROR_MESSAGES["NO_USER"])
                return

            # Sync metadata
            await sync_stripe_metadata(subscription_id, user_id, subscription_type)

            # Activate subscription
            await activate_subscription(
                user_id,
                subscription_id,
                subscription_type,
                customer_id,
            )

            # Update scan if present
            if scan_id:
                await StripeWebhookHelper.scan_repo.update_scan_paid_status(
                    UUID(scan_id), True, True
                )
                await PaymentRepository.update_subscription_payment(UUID(scan_id), user_id)
                logger.info(f"Updated scan {scan_id} payment status")

            logger.info(f"Subscription created for user {user.githubId}")

        except Exception as e:
            logger.error(f"Error handling subscription creation: {str(e)}")

    @staticmethod
    async def handle_invoice_payment(event: dict):
        """Handle recurring subscription payments"""
        invoice = event["data"]["object"]
        subscription_id = invoice.get("subscription")
        customer_id = invoice.get("customer")
        expire = invoice["lines"]["data"][0]["period"]["end"]

        if not subscription_id or not customer_id:
            logger.error(StripeWebhookHelper.ERROR_MESSAGES["MISSING_DATA"])
            return

        try:
            subscription = await verify_stripe_subscription(subscription_id)
            if not subscription:
                return

            subscription_type = subscription.metadata.get("type")
            if subscription_type not in SUBSCRIPTION_SETTINGS:
                logger.error(f"Invalid subscription type: {subscription_type}")
                return

            # Find user using utility function
            user = await find_user(customer_id=customer_id, subscription_id=subscription_id)
            if not user:
                logger.error(StripeWebhookHelper.ERROR_MESSAGES["NO_USER"])
                return

            # Sync metadata if user found
            await sync_stripe_metadata(subscription_id, user.githubId, subscription_type)

            # Renew subscription credits
            await UserRepository.renew_subscription_credits(user, expire)
            logger.info(f"Subscription renewed for user {user.githubId}")

        except Exception as e:
            logger.error(f"Error handling invoice payment: {str(e)}")

    @staticmethod
    async def handle_subscription_deleted(event: dict):
        """Handle subscription cancellation/deletion"""
        try:
            subscription = event["data"]["object"]
            metadata = subscription.get("metadata", {})
            user_id = metadata.get("userId")
            subscription_id = subscription["id"]

            # Find user using utility function
            user = await find_user(subscription_id=subscription_id, user_id=user_id)
            if not user:
                logger.error(StripeWebhookHelper.ERROR_MESSAGES["NO_USER"])
                return

            await deactivate_subscription(user.githubId)
            logger.info(f"Subscription deleted for user {user.githubId}")

        except Exception as e:
            logger.error(f"Error handling subscription deletion: {str(e)}")

    @staticmethod
    async def handle_subscription_updated(event: dict):
        """Handle subscription updates (status changes, plan changes, etc.)"""
        try:
            subscription = event["data"]["object"]
            metadata = subscription.get("metadata", {})
            user_id = metadata.get("userId")
            status = subscription.get("status")
            subscription_id = subscription["id"]
            subscription_type = metadata.get("type")
            customer_id = subscription.get("customer")
            scan_id = metadata.get("scanId")

            # Validate status
            valid_statuses = [
                "active",
                "past_due",
                "unpaid",
                "canceled",
                "incomplete",
                "incomplete_expired",
            ]
            if status not in valid_statuses:
                logger.warning(StripeWebhookHelper.ERROR_MESSAGES["INVALID_STATUS"])
                return

            # Validate subscription type
            if subscription_type not in SUBSCRIPTION_SETTINGS:
                logger.error(f"Invalid subscription type: {subscription_type}")
                return

            # Find user
            user = await find_user(subscription_id=subscription_id, user_id=user_id)
            if not user:
                logger.error(StripeWebhookHelper.ERROR_MESSAGES["NO_USER"])
                return

            # Handle status changes
            if status == "past_due":
                logger.warning(f"Subscription payment past due for user {user.githubId}")
                return

            if status == "unpaid":
                await UserRepository.deactivate_subscription(user)
                logger.warning(f"Subscription marked unpaid for user {user.githubId}")
                return

            if status != "active":
                logger.info(
                    f"Subscription status {status} requires no action for user {user.githubId}"
                )
                return

            # Handle active status
            needs_activation = (
                not user.subscription.isActive
                or user.subscription.stripeSubscriptionId != subscription_id
            )

            if not needs_activation:
                logger.info(f"Subscription already active for user {user.githubId}")
                return

            # Activate subscription
            await activate_subscription(
                user.githubId,
                subscription_id,
                subscription_type,
                customer_id,
            )

            # Update scan if present
            if scan_id:
                await StripeWebhookHelper.scan_repo.update_scan_paid_status(
                    UUID(scan_id), True, True
                )
                await PaymentRepository.update_subscription_payment(UUID(scan_id), user_id)
                logger.info(f"Updated scan {scan_id} payment status")

            logger.info(f"Subscription updated for user {user.githubId} - Status: {status}")

        except Exception as e:
            logger.error(f"Error handling subscription update: {str(e)}")
