from datetime import datetime
from typing import Optional
from uuid import UUID

from fastapi import HTTPException

from config.subscription_settings import SUBSCRIPTION_SETTINGS
from core.db.repositories.credit_transaction import CreditTransactionRepository
from core.db.repositories.payment import PaymentRepository
from core.db.repositories.scan import ScanRepository
from core.db.repositories.user import UserRepository
from core.models.credit_transaction import CreditTransaction, TransactionStatus, TransactionType
from core.models.payment import Payment
from core.models.user import SubscriptionType, User
from core.utils.email_utils import send_failed_refund_email
from core.utils.logger import logger


class CreditHelper:
    @staticmethod
    async def deduct_credit(user_id: str, scan_id: UUID, repository_name: str):
        """
        Deducts one credit for a pro scan.
        Should only be called after verifying user has active subscription.
        Returns True if deduction was successful.
        """
        # Find user and verify credits
        user = await UserRepository.get_by_github_id(user_id)
        if not user or user.subscription.credits <= 0:
            logger.error(f"No credits available for user {user_id}, scan {scan_id}")
            raise HTTPException(status_code=400, detail="No credits available")

        # Atomic credit deduction
        if not await _update_user_credits(user, -1):
            logger.error(f"Failed to deduct credit for user {user_id}, scan {scan_id}")
            raise HTTPException(status_code=400, detail="Failed to deduct credit")

        # Process credit transaction and update scan status
        await _process_scan_credit(
            user_id=user_id,
            scan_id=scan_id,
            repository_name=repository_name,
            subscription_type=user.subscription.type,
            renewal_period=user.subscription.lastRenewalAt,
        )

    @staticmethod
    async def refund_credit(user_id: str, scan_id: UUID) -> None:
        """Refunds a credit for a failed scan."""
        # Find original transaction
        transaction = await CreditTransaction.find_one(
            {"scanId": scan_id, "userId": user_id, "status": TransactionStatus.COMPLETED}
        )
        if not transaction:
            logger.error(f"No transaction found for refund: scan {scan_id}")

            return
        # Verify user and subscription
        user = await UserRepository.get_by_github_id(user_id)
        if not user or not user.subscription.isActive:
            logger.error(f"Invalid user/subscription for refund: {user_id}")
            return

        # Don't refund if in new period
        if (
            user.subscription.lastRenewalAt
            and transaction.timestamp < user.subscription.lastRenewalAt
        ):
            logger.info(f"Refund rejected - new period: {user_id}, scan {scan_id}")

        # Get monthly credit limit
        monthly_credits = SUBSCRIPTION_SETTINGS[user.subscription.type].get("monthly_credits", 0)

        # Atomic credit refund with monthly limit
        if not await _update_user_credits(user, 1, monthly_credits):
            send_failed_refund_email(user_id, scan_id)
            logger.error(f"Failed to refund credit: {user_id}, scan {scan_id}")

        # Process credit transaction
        await _process_scan_credit(
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
    subscription_type: SubscriptionType,
    renewal_period: Optional[datetime],
    is_refund: bool = False,
) -> None:
    """
    Handle credit transaction and scan status update.
    Used for both deduction and refund operations.
    """
    try:
        await CreditTransactionRepository.create_credit_transaction(
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

        # Update payment record
        existing_payment = await Payment.find_one(Payment.scan_id == scan_id)
        if not existing_payment:
            logger.error(f"No payment record found for scan {scan_id}")
            raise HTTPException(status_code=404, detail="Payment record not found")

        if is_refund:
            await PaymentRepository.update_failed_payment(scan_id, user_id)
            logger.info(f"Credit refunded for user {user_id}, scan {scan_id}")
        else:
            await PaymentRepository.update_subscription_payment(scan_id, user_id)
            await ScanRepository.update_scan_paid_status(scan_id, True, False)
            logger.info(f"Credit deducted for user {user_id}, scan {scan_id}")

    except HTTPException as e:
        logger.error(f"Failed to process credit transaction: {str(e)}")
        raise e
    except Exception as e:
        logger.error(f"Failed to process credit transaction: {str(e)}")
        raise e


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
