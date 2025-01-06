from datetime import datetime, timezone
from typing import Optional
from uuid import UUID

from fastapi import HTTPException

from core.models.payment import Payment, PaymentStatus, PaymentType
from core.utils.logger import logger


class PaymentRepository:
    """Repository for managing payment records in the database."""

    @staticmethod
    async def get_by_event_id(event_id: str) -> Optional[Payment]:
        """Find payment by Stripe event ID."""
        return await Payment.find_one({"event_id": event_id})

    @staticmethod
    async def get_by_session_id(session_id: str) -> Optional[Payment]:
        """Find payment by Stripe session ID."""
        return await Payment.find_one({"stripeSessionId": session_id})

    @staticmethod
    async def get_by_scan_id(scan_id: UUID) -> Optional[Payment]:
        """Find payment by scan ID."""
        return await Payment.find_one({"scan_id": scan_id})

    @staticmethod
    async def create_initial_payment(scan_id: UUID, user_id: str) -> Payment:
        """Create initial pending payment record for a new scan."""
        try:
            existing_payment = await PaymentRepository.get_by_scan_id(scan_id)
            if existing_payment:
                logger.info(f"Payment record already exists for scan {scan_id}")
                return existing_payment

            payment = Payment(
                scan_id=scan_id,
                user_id=user_id,
                amount=0,
                currency="usd",
                status=PaymentStatus.PENDING,
                event_id="Scan initialization",
                stripeSessionId="SCAN_INIT",
                payment_type=PaymentType.ONE_TIME,
            )
            await payment.save()
            logger.info(f"Created initial payment record for scan {scan_id}")
            return payment

        except Exception as e:
            logger.error(f"Error creating initial payment record for scan {scan_id}: {str(e)}")
            raise HTTPException(
                status_code=500, detail="Failed to create initial payment record"
            ) from e

    @staticmethod
    async def update_success_payment(
        scan_id: UUID,
        user_id: str,
        session_id: str,
        amount: float,
        event_id: Optional[str] = None,
    ) -> Payment:
        """
        Update payment record for a successful payment.

        Args:
            scan_id: (UUID) UUID of the scan
            user_id: (str) ID of the user making payment
            session_id: (str) Stripe session ID
            amount: (float) Payment amount
            event_id: (Optional[str]) Stripe event ID

        Returns:
            Updated Payment object
        """

        return await PaymentRepository._update_payment(
            scan_id=scan_id,
            user_id=user_id,
            status=PaymentStatus.COMPLETED,
            payment_type=PaymentType.ONE_TIME,
            event_id=event_id or "Payment completed",
            amount=amount,
            stripe_session_id=session_id,
            error_message="Failed to update success payment",
        )

    @staticmethod
    async def update_free_payment(scan_id: UUID, user_id: str) -> Payment:
        """Update payment record for a free scan (0-1 findings)."""
        return await PaymentRepository._update_payment(
            scan_id=scan_id,
            user_id=user_id,
            status=PaymentStatus.COMPLETED,
            payment_type=PaymentType.FREE,
            event_id="Free scan (0-1 findings)",
            amount=0.0,
            stripe_session_id="FREE_SCAN",
            error_message="Failed to update free payment",
        )

    @staticmethod
    async def update_subscription_payment(scan_id: UUID, user_id: str) -> Payment:
        """Update payment record for a free scan (0-1 findings)."""
        return await PaymentRepository._update_payment(
            scan_id=scan_id,
            user_id=user_id,
            status=PaymentStatus.COMPLETED,
            payment_type=PaymentType.SUBSCRIPTION,
            event_id="Subscription credit used",
            amount=0.0,
            stripe_session_id="SUBSCRIPTION_SCAN",
            error_message="Failed to update subscription payment",
        )

    @staticmethod
    async def update_failed_payment(
        scan_id: UUID, user_id: str, event_id: str = "Failed scan"
    ) -> Payment:
        """Update payment record for a failed scan."""
        return await PaymentRepository._update_payment(
            scan_id=scan_id,
            user_id=user_id,
            status=PaymentStatus.FAILED,
            payment_type=PaymentType.FAILED,
            event_id=event_id,
            amount=0.0,
            stripe_session_id="FAILED_SCAN",
            error_message="Failed to update failed payment",
        )

    @staticmethod
    async def _update_payment(
        scan_id: UUID,
        user_id: str,
        status: PaymentStatus,
        payment_type: PaymentType,
        event_id: str,
        amount: float,
        stripe_session_id: str,
        error_message: str,
        currency: str = "usd",
    ) -> Payment:
        """
        Internal method to update or create a payment record.

        Args:
            scan_id: (UUID) UUID of the scan
            user_id: (str) ID of the user making payment
            status: (PaymentStatus) New payment status
            payment_type: (PaymentType) Type of payment
            event_id: (Optional[str]) Stripe event ID
            amount: (float) Payment amount
            stripe_session_id: (str) Stripe session ID
            error_message: (str) Error message
            currency: (str) Currency

        Returns:
            Updated Payment object

        Raises:
            HTTPException: If update fails

        """
        try:
            existing_payment = await PaymentRepository.get_by_scan_id(scan_id)

            if existing_payment:
                # Only update if status is different (avoid unnecessary updates)
                if existing_payment.status != status:
                    existing_payment.status = status
                    existing_payment.payment_type = payment_type
                    existing_payment.event_id = event_id
                    existing_payment.amount = amount
                    existing_payment.stripeSessionId = stripe_session_id
                    existing_payment.updatedAt = datetime.now(timezone.utc)
                    await existing_payment.save()
                return existing_payment

            # Create new payment if none exists
            payment = Payment(
                scan_id=scan_id,
                user_id=user_id,
                status=status,
                payment_type=payment_type,
                event_id=event_id,
                amount=amount,
                currency=currency,
                stripeSessionId=stripe_session_id,
            )
            await payment.save()
            return payment

        except Exception as e:
            logger.error(f"Error updating payment for scan {scan_id}: {str(e)}")
            raise HTTPException(status_code=500, detail=error_message) from e
