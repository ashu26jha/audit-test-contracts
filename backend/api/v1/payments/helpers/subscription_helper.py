import stripe

from core.db.repositories.user import UserRepository
from core.utils.logger import logger


async def activate_subscription(user_id: str, subscription_id: str):
    """Activate user subscription and set up initial state"""
    user = await UserRepository.get_by_github_id(user_id)
    if not user:
        logger.error(f"User not found for subscription activation: {user_id}")
        return

    try:
        # Create or get Stripe customer
        customer_id = user.subscription.stripeCustomerId
        if not customer_id:
            customer = stripe.Customer.create(
                email=user.email, metadata={"githubId": user.githubId}
            )
            customer_id = customer.id

        await UserRepository.activate_subscription(
            user, subscription_id=subscription_id, customer_id=customer_id
        )
        logger.info(f"Subscription activated for user {user_id}")
    except stripe.error.StripeError as e:
        logger.error(f"Stripe error in subscription activation: {str(e)}")
    except Exception as e:
        logger.error(f"Error activating subscription: {str(e)}")


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
