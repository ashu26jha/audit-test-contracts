from datetime import datetime, timezone
from typing import List
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
        self.contract_files = []
        self.contract_address = request.contractAddress
        self.chain_id = request.chainId
        self.scan_id = scan_id
        self.user_id = request.userEmail

    async def create_agentic_scan_record(self, scan_number: int, contract_files: List[str]):
        # Create and store the new scan with initial status 'pending'
        new_scan = Scan(
            scan_id=self.scan_id,
            scan_number=scan_number,
            status="pending",
            startedAt=datetime.now(timezone.utc),
            contractFiles=contract_files,
            user_id=self.user_id,
            branchName="Agentic Scan Per Address",
            contract_address=self.contract_address,
            chain_id=str(self.chain_id),
            scan_type="Agentic Scan Per Address",
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

    async def count_lines_of_code(self, flattened_contracts: str) -> CodeAnalysisResult:
        # Count lines of code
        lines_of_code = await count_lines_of_code(flattened_contracts)

        # Update scan with lines of code
        await ScanRepository.update_scan_lines_of_code(self.scan_id, lines_of_code)

        return lines_of_code
