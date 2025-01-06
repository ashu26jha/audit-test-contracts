from datetime import datetime
from typing import Optional
from uuid import UUID

from fastapi import HTTPException

from core.models.credit_transaction import CreditTransaction, TransactionStatus, TransactionType
from core.utils import logger


class CreditTransactionRepository:
    @staticmethod
    async def get_by_scan_id(scan_id: UUID) -> Optional[CreditTransaction]:
        """Find credit transaction by scan ID."""
        return await CreditTransaction.find_one({"scanId": scan_id})

    @staticmethod
    async def create_credit_transaction(
        user_id: str,
        scan_id: UUID,
        repository_name: str,
        amount: bool,
        transaction_type: TransactionType,
        subscription_type: str,
        renewal_period: datetime,
    ) -> None:
        """Create a credit transaction."""
        try:
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
        except Exception as e:
            logger.error(f"Error creating credit transaction: {str(e)}")
            raise HTTPException(
                status_code=500, detail="Failed to create credit transaction"
            ) from e
