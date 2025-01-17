from datetime import datetime, timezone
from uuid import UUID

from api.v1.agentic.schema import PerAddressAgenticRequest
from api.v1.common.lines_of_code import count_lines_of_code
from core.db.repositories.scan import ScanRepository
from core.models.scan import CodeAnalysisResult, Scan, ScanResult
from core.utils.profiles import Profiles


class AgenticScanInitializer:
    def __init__(
        self,
        request: PerAddressAgenticRequest,
        scan_id: UUID,
    ):
        self.scan_id = scan_id
        self.chain_id = request.chainID
        self.contract_address = request.contractAddress
        self.contract_files = request.contractFiles

    @staticmethod
    async def create_agentic_scan_record(self, scan_number: int):
        # Create and store the new scan with initial status 'pending'
        new_scan = Scan(
            scan_id=self.scan_id,
            scan_number=scan_number,
            status="pending",
            startedAt=datetime.now(timezone.utc),
            contractFiles=self.contract_files,
            repositoryURL=self.contract_address,
            repositoryName=self.chain_id,
            branchName="Agentic Scan Per Address",
        )
        await ScanRepository.store_scan(new_scan)

        # Create and store an initial empty scan result
        initial_scan_result = ScanResult(
            scan_id=self.scan_id,
            scan_number=scan_number,
            summary=None,
            info_message="Agentic scan in progress",
            type=Profiles.NONE,
            total_findings=0,
            findings=[],
        )
        await ScanRepository.store_scan_result(initial_scan_result)

    @staticmethod
    async def count_lines_of_code(self, flattened_contracts: str) -> CodeAnalysisResult:
        # Count lines of code
        lines_of_code = await count_lines_of_code(flattened_contracts)

        # Update scan with lines of code
        await ScanRepository.update_scan_lines_of_code(self.scan_id, lines_of_code)

        return lines_of_code
