from typing import Optional
from uuid import UUID

import stripe

from api.v1.payments.helpers.get_result_url import get_payment_urls
from config.settings import FRONTEND_URL
from config.subscription_settings import SUBSCRIPTION_SETTINGS
from core.db.repositories.user import UserRepository
from core.models.user import SubscriptionType, User
from core.utils import logger
from core.utils.errors import PaymentError, SubscriptionError
from core.utils.validate import validate_user_scan_access


class StripeSubscriptionHelper:
    user_repo = UserRepository()

    @staticmethod
    async def create_subscription_session(
        user: User, subscription_type: SubscriptionType, scan_id: Optional[str] = None
    ):
        """Create subscription session for pro plan."""
        try:
            # Ensure user has subscription data
            if not user.subscription:
                user = await UserRepository.ensure_user_subscription_data(user)

            # Check if the scan exists and belongs to the user
            if scan_id:
                scan_uuid = UUID(scan_id)
                await validate_user_scan_access(scan_uuid, user)

            subscription = SUBSCRIPTION_SETTINGS[subscription_type]

            if not subscription["price"]:
                logger.error(f"error validating stripe price ID for user {user.githubId}")
                raise SubscriptionError(
                    message="Stripe subscription price ID is not configured",
                    details={"user_id": user.githubId, "error_type": "price_id_not_found"},
                )

            success_url, cancel_url = get_payment_urls()

            try:
                metadata = {
                    "userId": user.githubId,
                    "scanId": scan_id or "",
                    "type": subscription_type.value,
                }

                return stripe.checkout.Session.create(
                    customer=user.subscription.stripeCustomerId,
                    customer_email=user.email if not user.subscription.stripeCustomerId else None,
                    billing_address_collection="auto",
                    line_items=[
                        {
                            "price": subscription["price"],
                            "quantity": 1,
                        }
                    ],
                    mode="subscription",
                    payment_method_collection="if_required",
                    allow_promotion_codes=True,
                    success_url=success_url,
                    cancel_url=cancel_url,
                    metadata=metadata,
                    subscription_data={"metadata": metadata},
                )
            except stripe.error.StripeError as e:
                raise PaymentError(
                    message="Failed creating checkout session",
                    details={
                        "user_id": user.githubId,
                        "price_id": subscription["price"],
                        "error": str(e),
                    },
                )
        except (SubscriptionError, PaymentError, PermissionError):
            raise
        except Exception as e:
            logger.error(
                f"Unexpected error creating stripe checkout session for user {user.githubId}: {str(e)}"
            )
            raise SubscriptionError(
                message="Failed to create stripe checkout session",
                details={
                    "user_id": user.githubId,
                    "error_type": "unexpected_error",
                    "error": str(e),
                },
            ) from e

    @staticmethod
    async def create_enterprise_subscription_session(user_id: str) -> stripe.checkout.Session:
        """Create subscription session for enterprise plan without payment method."""
        try:
            subscription = SUBSCRIPTION_SETTINGS[SubscriptionType.ENTERPRISE]
            if not subscription["price"]:
                logger.error(f"error validating stripe price ID for user {user_id}")
                raise SubscriptionError(
                    message="Stripe subscription price ID is not configured",
                    details={"user_id": user_id, "error_type": "price_id_not_found"},
                )

            success_url, cancel_url = get_payment_urls()

            try:
                metadata = {
                    "userId": user_id,
                    "type": SubscriptionType.ENTERPRISE.value,
                }

                return stripe.checkout.Session.create(
                    customer_email=None,
                    billing_address_collection="auto",
                    line_items=[
                        {
                            "price": subscription["price"],
                            "quantity": 1,
                        }
                    ],
                    mode="subscription",
                    payment_method_collection="if_required",
                    allow_promotion_codes=True,
                    success_url=success_url,
                    cancel_url=cancel_url,
                    metadata=metadata,
                    subscription_data={"metadata": metadata},
                )
            except stripe.error.StripeError as e:
                logger.error(
                    f"Failed creating stripe checkout session for user {user_id}: {str(e)}"
                )
                raise PaymentError(
                    message="Failed creating checkout session",
                    details={
                        "user_id": user_id,
                        "price_id": subscription["price"],
                        "error": str(e),
                    },
                )
        except (SubscriptionError, PaymentError):
            raise
        except Exception as e:
            logger.error(
                f"Unexpected error creating stripe checkout session for user {user_id}: {str(e)}"
            )
            raise SubscriptionError(
                message="Failed to create stripe checkout session",
                details={
                    "user_id": user_id,
                    "error_type": "unexpected_error",
                    "error": str(e),
                },
            ) from e

    @staticmethod
    async def create_portal_session(user: User) -> stripe.billing_portal.Session:
        """Create a Stripe billing portal session."""
        if not user.subscription.stripeCustomerId:
            logger.error(f"No active subscription found for user {user.githubId}")
            raise SubscriptionError(
                message="No active subscription found",
                details={"user_id": user.githubId},
            )
        try:
            return stripe.billing_portal.Session.create(
                customer=user.subscription.stripeCustomerId,
                return_url=f"{FRONTEND_URL}/dashboard",
            )
        except stripe.error.StripeError as e:
            logger.error(
                f"Failed creating stripe billing portal session for user {user.githubId}: {str(e)}"
            )
            raise SubscriptionError(
                message="Failed creating billing portal session",
                details={
                    "user_id": user.githubId,
                    "error": str(e),
                },
            ) from e
