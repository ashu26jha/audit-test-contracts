from datetime import datetime, timezone

from core.db.repositories.scan import ScanRepository
from core.models.scan import Scan
from core.scanners.base_scan_initializer import BaseScanInitializer
from core.schemas.context_protocols import ChainContext
from core.schemas.scan_schema import ScanType
from core.utils.errors import UnsupportedOperationError


class AgenticScanInitializer(BaseScanInitializer):
    """Agentic-specific scan initialization logic."""

    async def validate_request(self) -> None:
        """Validate the request for the scan."""
        pass

    async def create_scan_record(self) -> None:
        """Create the initial scan record with agentic-specific details."""

        if not isinstance(self.context, ChainContext):
            raise UnsupportedOperationError(
                f"Context type {type(self.context).__name__} does not support GitHub operations"
            )

        # Get next scan number
        scan_number = await Scan.get_next_agentic_scan_number(self.context.contract_address)
        scan_number = scan_number or 1
        self.scan_number = scan_number

        # Create scan record
        new_scan = Scan(
            scan_id=self.scan_id,
            scan_type=ScanType.AGENTIC,
            scan_number=scan_number,
            user_id=self.context.user_email,  # use user_email for Agentic
            status="pending",
            startedAt=datetime.now(timezone.utc),
            contractFiles=self.context.contract_files,
            branchName="Agentic Scan Per Address",
            contract_address=self.context.contract_address,
            chain_id=str(self.context.chain_id),
        )

        # Store scan and create initial result
        await ScanRepository.store_scan(new_scan)
