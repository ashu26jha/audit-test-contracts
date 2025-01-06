from fastapi import HTTPException

from api.v1.audit_agent.schema import ScanContext
from api.v1.payments.helpers.credits import CreditHelper
from core.db.repositories.payment import PaymentRepository
from core.db.repositories.scan import ScanRepository


class PaymentHandler:
    def __init__(self, context: ScanContext, total_findings: int = 0):
        self.user_id = context.user_id
        self.scan_id = context.scan_id
        self.is_pro_scan = context.is_pro_scan
        self.total_findings = total_findings
        self.payment_repo = PaymentRepository()

    async def initialize_payment(self) -> None:
        """Creates an initial payment record when a scan starts."""
        await self.payment_repo.create_initial_payment(self.scan_id, self.user_id)

    async def finalize_payment(self) -> None:
        """
        Manages the payment logic based on the number of findings.
        Updates payment status and handles related database operations.
        """
        scan = await ScanRepository.get_scan(self.scan_id)
        if not scan:
            raise HTTPException(status_code=404, detail="Scan not found")

        # Handle failed scans
        if scan.status == "failed":
            await ScanRepository.update_scan_paid_status(
                self.scan_id,
                paid_status=False,
                discount_applied=False,
            )
            await self.payment_repo.update_failed_payment(self.scan_id, self.user_id)
            if self.is_pro_scan:
                await CreditHelper.refund_credit(self.user_id, self.scan_id)

        # Handle free scans (0-1 findings)
        if self.total_findings <= 1:
            await ScanRepository.update_scan_paid_status(
                self.scan_id,
                paid_status=True,
                discount_applied=False,
            )
            await self.payment_repo.update_free_payment(self.scan_id, self.user_id)

        # For scans with 2+ findings:
        # If the user has a valid voucher, the payment system will handle it separately
        # by setting both paid_status=True and discount_applied=True
        # If it's a regular paid scan, the payment system will set paid_status=True
        # Both these cases are handled outside this class
