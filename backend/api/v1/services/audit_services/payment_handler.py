from datetime import datetime, timezone
from uuid import UUID

from fastapi import HTTPException

from api.v1.models.payment import Payment, PaymentStatus, PaymentType
from api.v1.models.user import User
from api.v1.services import scan_history_service
from api.v1.services.payments.stripe_subscription_service import refund_credit
from common.logger import logger


class PaymentHandler:
    def __init__(
        self, user: User, scan_id: UUID, is_pro_scan: bool = False, total_findings: int = 0
    ):
        self.user = user
        self.scan_id = scan_id
        self.is_pro_scan = is_pro_scan
        self.total_findings = total_findings

    async def process_payment(self) -> None:
        """
        Manages the payment logic based on the number of findings.
        Updates payment status and handles related database operations.
        """
        scan = await scan_history_service.get_scan(self.scan_id)
        if not scan:
            raise HTTPException(status_code=404, detail="Scan not found")

        # Handle failed scans
        if scan.status == "failed":
            await scan_history_service.update_scan_paid_status(
                self.scan_id,
                paid_status=False,
                discount_applied=False,
            )
            await self._create_failed_scan_payment_record()
            if self.is_pro_scan:
                await refund_credit(self.user.githubId, self.scan_id)
            return

        # Handle free scans (0-1 findings)
        if self.total_findings <= 1:
            await scan_history_service.update_scan_paid_status(
                self.scan_id,
                paid_status=True,
                discount_applied=False,
            )
            await self._create_free_payment_record()
            return

        # For scans with 2+ findings:
        # If the user has a valid voucher, the payment system will handle it separately
        # by setting both paid_status=True and discount_applied=True
        # If it's a regular paid scan, the payment system will set paid_status=True
        # Both these cases are handled outside this class

    async def _create_free_payment_record(self) -> None:
        """
        Creates or updates a payment record for free scans (0-1 findings).
        """
        try:
            existing_payment = await Payment.find_one(Payment.scan_id == self.scan_id)

            if not existing_payment:
                payment = Payment(
                    scan_id=self.scan_id,
                    amount=0.0,
                    currency="USD",
                    status=PaymentStatus.COMPLETED,
                    event_id="Free scan (0-1 findings)",
                    user_id=self.user.githubId,
                    stripeSessionId="FREE_SCAN",
                    payment_type=PaymentType.FREE,
                )
                await payment.save()
                logger.info(
                    f"Created free payment record for scan {self.scan_id} "
                    f"with {self.total_findings} findings"
                )
            else:
                if existing_payment.status != PaymentStatus.COMPLETED:
                    existing_payment.status = PaymentStatus.COMPLETED
                    existing_payment.payment_type = PaymentType.FREE
                    existing_payment.updatedAt = datetime.now(timezone.utc)
                    await existing_payment.save()
                    logger.info(
                        f"Updated existing payment to completed for scan {self.scan_id} "
                        f"with {self.total_findings} findings"
                    )

        except Exception as e:
            logger.error(
                f"Error creating/updating payment record for scan {self.scan_id}: {str(e)}"
            )

    async def _create_failed_scan_payment_record(self) -> None:
        """
        Creates or updates a payment record for failed scans.
        """
        try:
            existing_payment = await Payment.find_one(Payment.scan_id == self.scan_id)

            if not existing_payment:
                payment = Payment(
                    scan_id=self.scan_id,
                    amount=0.0,
                    currency="USD",
                    status=PaymentStatus.FAILED,
                    event_id="Failed scan",
                    user_id=self.user.githubId,
                    stripeSessionId="FAILED_SCAN",
                    payment_type=PaymentType.FAILED,
                )
                await payment.save()
                logger.info(f"Created failed payment record for scan {self.scan_id}")
            else:
                if existing_payment.status != PaymentStatus.FAILED:
                    existing_payment.status = PaymentStatus.FAILED
                    existing_payment.payment_type = PaymentType.FAILED
                    existing_payment.updatedAt = datetime.now(timezone.utc)
                    await existing_payment.save()
                    logger.info(f"Updated existing payment to failed for scan {self.scan_id}")

        except Exception as e:
            logger.error(
                f"Error creating/updating payment record for failed scan {self.scan_id}: {str(e)}"
            )

    async def create_initial_payment_record(self) -> None:
        """
        Creates an initial payment record when a scan starts.
        This ensures we have a payment record for every scan.
        """
        try:
            existing_payment = await Payment.find_one(Payment.scan_id == self.scan_id)

            if not existing_payment:
                payment = Payment(
                    scan_id=self.scan_id,
                    amount=0,
                    currency="usd",
                    status=PaymentStatus.PENDING,
                    event_id="Scan initialization",
                    user_id=self.user.githubId,
                    stripeSessionId="SCAN_INIT",
                    payment_type=PaymentType.ONE_TIME,  # Will be updated later if subscription
                )
                await payment.save()
                logger.info(f"Created initial payment record for scan {self.scan_id}")
            else:
                logger.info(f"Payment record already exists for scan {self.scan_id}")

        except Exception as e:
            logger.error(f"Error creating initial payment record for scan {self.scan_id}: {str(e)}")
            # Don't raise the exception as we don't want to block scan initialization
