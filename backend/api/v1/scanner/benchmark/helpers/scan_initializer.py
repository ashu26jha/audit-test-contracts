from datetime import datetime, timezone

from core.db.repositories.scan import ScanRepository
from core.models.scan import Scan
from core.scanners.base_scan_initializer import BaseScanInitializer
from core.schemas.scan_schema import ScanType


class BenchmarkScanInitializer(BaseScanInitializer):
    """Benchmark-specific scan initialization logic."""

    async def validate_request(self) -> None:
        """Validate repository and contract files."""
        # No validation needed for benchmark scans
        pass

    async def create_scan_record(self) -> None:
        """Create the initial scan record with benchmark-specific details."""
        # Create scan record
        new_scan = Scan(
            scan_id=self.scan_id,
            scan_type=ScanType.BENCHMARK,
            scan_number=1,  # Always 1 for benchmarks
            user_id="benchmark",
            status="pending",
            startedAt=datetime.now(timezone.utc),
            contractFiles=self.context.contract_files,
            repositoryURL=self.context.repository_url,
            repositoryName=self.context.repository_name if self.context.repository_name else "",
            branchName=self.context.branch_name,
        )

        # Store scan and create initial result
        await ScanRepository.store_scan(new_scan)
