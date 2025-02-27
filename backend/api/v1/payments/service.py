import stripe
from fastapi import HTTPException

from config.settings import STRIPE_API_KEY
from core.db.repositories.user import UserRepository
from core.models.user import SubscriptionType, User
from core.utils import logger
from core.utils.errors import AuthError, SubscriptionError

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
                logger.error(f"User with github_id {github_id} not found")
                raise AuthError(message="User not found", details={"github_id": github_id})
        elif email:
            user = await UserRepository.get_by_email(email)
            if not user:
                logger.error(f"User with email {email} not found")
                raise AuthError(message="User not found", details={"email": email})
        else:
            logger.error("No email or github_id provided")
            raise AuthError(message="Either email or github_id must be provided")

        if user.subscription.isActive and user.subscription.type == SubscriptionType.ENTERPRISE:
            logger.error(f"Enterprise subscription already active for user {user.githubId}")
            raise SubscriptionError(
                message="Enterprise subscription already active",
                details={"user_id": user.githubId},
            )

        return await StripeSubscriptionHelper.create_enterprise_subscription_session(
            user_id=user.githubId
        )
