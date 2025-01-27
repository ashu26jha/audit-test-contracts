from typing import Optional
from uuid import UUID

import stripe
from fastapi import HTTPException

from api.v1.payments.helpers.get_result_url import get_payment_urls
from config.settings import FRONTEND_URL
from config.subscription_settings import SUBSCRIPTION_SETTINGS
from core.db.repositories.user import UserRepository
from core.models.user import SubscriptionType, User
from core.utils.validate import validate_user_scan_access


class StripeSubscriptionHelper:
    user_repo = UserRepository()

    @staticmethod
    async def create_subscription_session(
        user: User, subscription_type: SubscriptionType, scan_id: Optional[str] = None
    ):
        """Create subscription session for pro plan."""
        # Ensure user has subscription data
        if not user.subscription:
            user = await UserRepository.ensure_user_subscription_data(user)

        # Check if the scan exists and belongs to the user
        if scan_id:
            try:
                scan_uuid = UUID(scan_id)
                await validate_user_scan_access(scan_uuid, user)
            except ValueError as e:
                raise HTTPException(status_code=400, detail="Invalid scan ID format") from e

        subscription = SUBSCRIPTION_SETTINGS[subscription_type]

        if not subscription["price"]:
            raise HTTPException(
                status_code=500, detail="Stripe subscription price ID is not configured"
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
            raise HTTPException(status_code=400, detail=str(e)) from e

    @staticmethod
    async def create_enterprise_subscription_session(user_id: str) -> stripe.checkout.Session:
        """Create subscription session for enterprise plan without payment method."""

        subscription = SUBSCRIPTION_SETTINGS[SubscriptionType.ENTERPRISE]
        if not subscription["price"]:
            raise HTTPException(
                status_code=500, detail="Stripe enterprise price ID is not configured"
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
            raise HTTPException(status_code=400, detail=str(e)) from e

    @staticmethod
    async def create_portal_session(user: User) -> stripe.billing_portal.Session:
        """Create a Stripe billing portal session."""
        if not user.subscription.stripeCustomerId:
            raise HTTPException(status_code=400, detail="No active subscription found")

        try:
            return stripe.billing_portal.Session.create(
                customer=user.subscription.stripeCustomerId,
                return_url=f"{FRONTEND_URL}/dashboard",
            )
        except stripe.error.StripeError as e:
            raise HTTPException(status_code=400, detail=str(e)) from e
