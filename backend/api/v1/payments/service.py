import stripe
from fastapi import HTTPException

from config.settings import STRIPE_API_KEY
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
