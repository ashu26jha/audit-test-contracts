import stripe

from core.db.repositories.user import UserRepository
from core.models.user import SubscriptionType
from core.utils.logger import logger


async def activate_subscription(
    user_id: str, subscription_id: str, subscription_type: SubscriptionType, customer_id: str = None
):
    """Activate user subscription and set up initial state"""
    user = await UserRepository.get_by_github_id(user_id)
    if not user:
        logger.error(f"User not found for subscription activation: {user_id}")
        return

    try:
        logger.info(f"Activating subscription for user {user.githubId}")
        await UserRepository.activate_subscription(
            user,
            subscription_id=subscription_id,
            subscription_type=subscription_type,
            customer_id=customer_id,
        )
        logger.info(f"Subscription activated for user {user_id} with customer {customer_id}")
    except stripe.error.StripeError as e:
        logger.error(f"Stripe error in subscription activation: {str(e)}")
        raise
    except Exception as e:
        logger.error(f"Error activating subscription: {str(e)}")
        raise


async def deactivate_subscription(user_id: str):
    """Deactivate a user's subscription"""
    user = await UserRepository.get_by_github_id(user_id)
    if not user:
        logger.error(f"User not found for subscription deactivation: {user_id}")
        return

    try:
        await UserRepository.deactivate_subscription(user)
        logger.info(f"Subscription deactivated for user {user_id}")
    except Exception as e:
        logger.error(f"Error deactivating subscription: {str(e)}")
