from api.v1.payments.helpers.credits import CreditHelper
from core.db.repositories.payment import PaymentRepository
from core.db.repositories.scan import ScanRepository
from core.models.payment import PaymentType
from core.schemas.context_protocols import GitHubContext
from core.schemas.scan_schema import BaseScanContext, ScanType
from core.utils.errors import PaymentError, UnsupportedOperationError
from core.utils.logger import logger


class PaymentHandler:
    """Handles payment processing for all scan types."""

    def __init__(self, context: BaseScanContext, total_findings: int = 0):
        self.context = context
        self.user_id = context.user_id
        self.scan_id = context.scan_id
        self.is_subscription_scan = context.is_subscription_scan
        self.total_findings = total_findings
        self.payment_repo = PaymentRepository()
        self.payment_type = self._get_payment_type()

    async def initialize_payment(self) -> None:
        """
        Creates an initial payment record when a scan starts.
        Deducts credit for subscription scans when ScanType is AuditAgent.
        """
        await self.payment_repo.create_initial_payment(
            scan_id=self.scan_id,
            user_id=self.user_id,
            payment_type=self.payment_type,
        )

        deduct_credit = (
            self.context.scan_type == ScanType.AUDIT_AGENT
            or self.context.scan_type == ScanType.CAIRO
        )

        if deduct_credit and self.is_subscription_scan:
            if not isinstance(self.context, GitHubContext):
                raise UnsupportedOperationError(
                    f"Context type {type(self.context).__name__} requires GitHub information for subscription scans"
                )

            await CreditHelper.deduct_credit(
                self.user_id, self.scan_id, self.context.repository_url
            )

    async def finalize_payment(self) -> None:
        """
        Manages the payment logic based on the number of findings.
        Updates payment status and handles related database operations.
        """
        try:
            scan = await ScanRepository.get_scan(self.scan_id)
            if not scan:
                raise PaymentError(
                    message="Scan not found",
                    details={"scan_id": self.scan_id, "type": self.payment_type},
                )

            # Handle failed scans
            if scan.status == "failed":
                await ScanRepository.update_scan_paid_status(
                    self.scan_id,
                    paid_status=False,
                    discount_applied=False,
                )
                await self.payment_repo.update_failed_payment(self.scan_id, self.user_id)
                if self.is_subscription_scan:
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
            # If it's a regular paid scan, the payment system will set paid_status=True
            # Both these cases are handled outside this class
            logger.info(f"[Payment] Scan {self.scan_id} updated with payment status")
        except Exception as e:
            if not isinstance(e, PaymentError):
                raise PaymentError(
                    message="Payment finalization failed", details={"error": str(e)}
                ) from e
            raise

    def _get_payment_type(self) -> PaymentType:
        """Determine payment type based on scan context."""
        if self.context.scan_type == ScanType.BENCHMARK:
            return PaymentType.BENCHMARK
        elif self.context.scan_type == ScanType.AGENTIC:
            return PaymentType.AGENTIC
        elif self.is_subscription_scan:
            return PaymentType.SUBSCRIPTION
        return PaymentType.ONE_TIME
