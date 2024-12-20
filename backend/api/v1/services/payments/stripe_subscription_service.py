from datetime import datetime
from typing import Optional
from uuid import UUID

from api.v1.models.credit_transaction import CreditTransaction, TransactionStatus, TransactionType
from api.v1.models.user import User
from api.v1.services.scan_history_service import update_scan_paid_status
from common.logger import logger
from config.subscription_settings import SUBSCRIPTION_SETTINGS


async def deduct_credit(user_id: str, scan_id: UUID, repository_name: str) -> bool:
    """
    Deducts one credit for a pro scan.
    Should only be called after verifying user has active subscription.
    Returns True if deduction was successful.
    """
    # Find user and verify credits
    user = await User.by_github_id(user_id)
    if not user or user.subscription.credits <= 0:
        logger.error(f"No credits available for user {user_id}, scan {scan_id}")
        return False

    # Atomic credit deduction
    if not await _update_user_credits(user, -1):
        logger.error(f"Failed to deduct credit for user {user_id}, scan {scan_id}")
        return False

    # Process credit transaction and update scan status
    return await _process_scan_credit(
        user_id=user_id,
        scan_id=scan_id,
        repository_name=repository_name,
        subscription_type=user.subscription.type,
        renewal_period=user.subscription.lastRenewalAt,
    )


async def refund_credit(user_id: str, scan_id: UUID) -> bool:
    """Refunds a credit for a failed scan."""
    # Find original transaction
    transaction = await CreditTransaction.find_one(
        {"scanId": scan_id, "userId": user_id, "status": TransactionStatus.COMPLETED}
    )
    if not transaction:
        logger.error(f"No transaction found for refund: scan {scan_id}")
        return False

    # Verify user and subscription
    user = await User.by_github_id(user_id)
    if not user or not user.subscription.isActive:
        logger.error(f"Invalid user/subscription for refund: {user_id}")
        return False

    # Don't refund if in new period
    if user.subscription.lastRenewalAt and transaction.timestamp < user.subscription.lastRenewalAt:
        logger.info(f"Refund rejected - new period: {user_id}, scan {scan_id}")
        return False

    # Get monthly credit limit
    monthly_credits = SUBSCRIPTION_SETTINGS[user.subscription.type].get("monthly_credits", 0)

    # Atomic credit refund with monthly limit
    if not await _update_user_credits(user, 1, monthly_credits):
        logger.error(f"Failed to refund credit: {user_id}, scan {scan_id}")
        return False

    # Process credit transaction
    return await _process_scan_credit(
        user_id=user_id,
        scan_id=scan_id,
        repository_name=transaction.repositoryName,
        subscription_type=user.subscription.type,
        renewal_period=user.subscription.lastRenewalAt,
        is_refund=True,
    )


async def _process_scan_credit(
    user_id: str,
    scan_id: UUID,
    repository_name: str,
    subscription_type: str,
    renewal_period: Optional[datetime],
    is_refund: bool = False,
) -> bool:
    """
    Handle credit transaction and scan status update.
    Used for both deduction and refund operations.
    """
    try:
        await _create_credit_transaction(
            user_id=user_id,
            scan_id=scan_id,
            repository_name=repository_name,
            amount=-1 if not is_refund else 1,
            transaction_type=(
                TransactionType.MANUAL_SCAN if not is_refund else TransactionType.REFUND
            ),
            subscription_type=subscription_type,
            renewal_period=renewal_period,
        )

        # Update scan status
        # For deductions, mark as paid
        # For refunds, we might want to add a "refunded" status
        if not is_refund:
            await update_scan_paid_status(scan_id, True, False)
            logger.info(f"Credit deducted for user {user_id}, scan {scan_id}")
        else:
            logger.info(f"Credit refunded for user {user_id}, scan {scan_id}")

        return True

    except Exception as e:
        logger.error(f"Failed to process credit transaction: {str(e)}")
        return False


async def _create_credit_transaction(
    user_id: str,
    scan_id: UUID,
    repository_name: str,
    amount: int,
    transaction_type: TransactionType,
    subscription_type: str,
    renewal_period: Optional[datetime],
) -> CreditTransaction:
    """Helper function to create and save a credit transaction."""
    transaction = CreditTransaction(
        userId=str(user_id),
        scanId=scan_id,
        repositoryName=str(repository_name),
        amount=amount,
        type=transaction_type,
        status=TransactionStatus.COMPLETED,
        subscription_type=str(subscription_type),
        renewal_period=renewal_period,
        metadata=None,
    )
    await transaction.save()
    return transaction


async def _update_user_credits(
    user: User,
    amount: int,
    monthly_limit: Optional[int] = None,
) -> bool:
    """Helper function to update user's credit balance."""
    update_query = {"$inc": {"subscription.credits": amount}}
    if monthly_limit is not None:
        update_query["$min"] = {"subscription.credits": monthly_limit}

    result = await user.update(update_query)
    return bool(result)
