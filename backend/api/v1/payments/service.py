import stripe
from fastapi import HTTPException

from config.settings import STRIPE_API_KEY
from core.db.repositories.user import UserRepository
from core.models.user import SubscriptionType, User
from core.utils import logger

from .helpers.stripe_subscription import StripeSubscriptionHelper
from .helpers.stripe_webhook import StripeWebhookHelper

stripe.api_key = STRIPE_API_KEY
if not STRIPE_API_KEY:
    MESSAGE = "Stripe API key is not set"
    logger.error(MESSAGE)
    raise HTTPException(status_code=500, detail=MESSAGE)


class StripeWebhookService:
    @staticmethod
    async def handle_webhook(payload: bytes, sig_header: str):
        return await StripeWebhookHelper.handle_webhook(payload, sig_header)


class StripeSubscriptionService:
    @staticmethod
    async def create_subscription_session(
        user: User, subscription_type: SubscriptionType, scan_id: str = None
    ) -> stripe.checkout.Session:
        return await StripeSubscriptionHelper.create_subscription_session(
            user, subscription_type, scan_id
        )

    @staticmethod
    async def create_portal_session(user: User) -> stripe.billing_portal.Session:
        return await StripeSubscriptionHelper.create_portal_session(user)

    @staticmethod
    async def create_enterprise_subscription_session(
        email: str = None, github_id: str = None
    ) -> stripe.checkout.Session:
        """Create a subscription session for enterprise plan without payment method."""
        user = None
        if github_id:
            user = await UserRepository.get_by_github_id(github_id)
            if not user:
                raise HTTPException(status_code=404, detail="User not found")
        elif email:
            user = await UserRepository.get_by_email(email)
            if not user:
                raise HTTPException(status_code=404, detail="User not found")
        else:
            raise HTTPException(
                status_code=400, detail="Either email or github_id must be provided"
            )

        if user.subscription.isActive and user.subscription.type == SubscriptionType.ENTERPRISE:
            raise HTTPException(status_code=400, detail="Enterprise subscription already active")

        return await StripeSubscriptionHelper.create_enterprise_subscription_session(
            email=user.email, user_id=user.githubId
        )
