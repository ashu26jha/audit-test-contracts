from typing import Any, Dict, Optional

import stripe

from core.db.repositories.user import UserRepository
from core.models.user import User
from core.utils.logger import logger


async def find_user(
    customer_id: Optional[str] = None,
    subscription_id: Optional[str] = None,
    user_id: Optional[str] = None,
) -> Optional[User]:
    """
    Standard user lookup function with consistent precedence.

    Args:
        customer_id: Stripe customer ID
        subscription_id: Stripe subscription ID
        user_id: User's GitHub ID

    Returns:
        User object if found, None otherwise
    """
    # 1. Try direct user_id first if provided
    if user_id:
        user = await UserRepository.get_by_github_id(user_id)
        if user:
            logger.info(f"Found user by github_id: {user_id}")
            return user

    # 2. Try customer_id next
    if customer_id:
        user = await UserRepository.get_by_customer_id(customer_id)
        if user:
            logger.info(f"Found user by customer_id: {customer_id}")
            return user

    # 3. Try subscription_id last
    if subscription_id:
        user = await UserRepository.get_by_subscription_id(subscription_id)
        if user:
            logger.info(f"Found user by subscription_id: {subscription_id}")
            return user

    return None


async def sync_stripe_metadata(
    subscription_id: str, user_id: str, subscription_type: str, scan_id: Optional[str] = None
) -> bool:
    """
    Ensure Stripe subscription metadata is in sync.

    Args:
        subscription_id: Stripe subscription ID
        user_id: User's GitHub ID
        subscription_type: Type of subscription
        scan_id: Optional scan ID

    Returns:
        bool: True if sync successful, False otherwise
    """
    try:
        metadata: Dict[str, Any] = {"userId": user_id, "type": subscription_type}
        if scan_id:
            metadata["scanId"] = scan_id

        stripe.Subscription.modify(subscription_id, metadata=metadata)
        logger.info(f"Updated subscription {subscription_id} metadata for user {user_id}")
        return True
    except stripe.error.StripeError as e:
        logger.error(f"Error updating subscription metadata: {str(e)}")
        return False


async def verify_stripe_subscription(subscription_id: str) -> Optional[stripe.Subscription]:
    """
    Verify if a Stripe subscription exists and is valid.

    Args:
        subscription_id: Stripe subscription ID

    Returns:
        Optional[stripe.Subscription]: Subscription object if valid, None otherwise
    """
    try:
        subscription = stripe.Subscription.retrieve(subscription_id)
        return subscription
    except stripe.error.StripeError as e:
        logger.error(f"Error verifying subscription {subscription_id}: {str(e)}")
        return None
