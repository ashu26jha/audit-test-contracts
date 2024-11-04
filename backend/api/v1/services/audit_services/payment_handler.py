from datetime import datetime, timezone
from uuid import UUID

from fastapi import HTTPException

from api.v1.models.payment import Payment, PaymentStatus
from api.v1.models.user import User
from api.v1.services import scan_history_service
from common.logger import logger


class PaymentHandler:
    def __init__(self, user: User, scan_id: UUID, total_findings: int):
        self.user = user
        self.scan_id = scan_id
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
            await scan_history_service.update_scan(
                self.scan_id,
                {
                    "paid_status": False,
                    "discount_applied": False,
                },
            )
            return

        # Handle free scans (0-1 findings)
        if self.total_findings <= 1:
            await scan_history_service.update_scan(
                self.scan_id,
                {
                    "paid_status": True,
                    "discount_applied": False,
                },
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
                    createdAt=datetime.now(timezone.utc),
                    updatedAt=datetime.now(timezone.utc),
                    event_id="Free scan (0-1 findings)",
                    user_id=str(self.user.id),
                    stripeSessionId="FREE_SCAN",
                )
                await payment.save()
                logger.info(
                    f"Created free payment record for scan {self.scan_id} "
                    f"with {self.total_findings} findings"
                )
            else:
                if existing_payment.status != PaymentStatus.COMPLETED:
                    existing_payment.status = PaymentStatus.COMPLETED
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
            # Don't raise the exception as the scan is still free regardless of payment record
