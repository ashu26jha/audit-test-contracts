import gc
from typing import List

from api.v1.audit_agent.schema import ScanContext
from api.v1.common import contract_utils
from api.v1.utilities.critics.service import CriticService
from core.db.repositories.scan import ScanRepository
from core.models.scan import Finding, ScanResult
from core.utils import logger
from core.utils.profiles import Profiles


class ResultProcessor:
    def __init__(
        self,
        context: ScanContext,
        combined_findings: List[Finding],
        flattened_contracts: str,
        summary_result: str,
        detected_type: Profiles,
    ):
        self.scan_id = context.scan_id
        self.user_id = context.user_id
        self.combined_findings: List[Finding] = []  # Initialize empty
        self.findings_before_removal = combined_findings  # Store initial findings
        self.selected_contracts = context.contract_files
        self.flattened_contracts = flattened_contracts
        self.summary_result = summary_result
        self.detected_type = detected_type

    async def process_results(self) -> None:
        """Process results sequentially: filter, deduplicate, then mitigate."""
        # 1. Filter findings to ensure they all belong to the selected contracts
        initial_count = len(self.findings_before_removal)
        self.findings_before_removal = contract_utils.filter_by_contracts(
            self.findings_before_removal, self.selected_contracts, contract_field="Contracts"
        )
        logger.logger.info(
            f"Filtered out {initial_count - len(self.findings_before_removal)} findings that didn't match selected contracts"
        )
        await ScanRepository.update_scan_progress(self.scan_id, 80)

        # 2. Perform deduplication and mitigation
        self.combined_findings = await CriticService.remove_duplicates(self.findings_before_removal)
        await ScanRepository.update_scan_progress(self.scan_id, 90)

        # 3. Perform mitigation
        self.combined_findings = await CriticService.mitigate_findings(
            findings=self.combined_findings,
            flattened_contracts=self.flattened_contracts,
        )
        await ScanRepository.update_scan_progress(self.scan_id, 100)
        self.flattened_contracts = None
        gc.collect()

        # 4. Update scan result in database
        result = await self._get_scan_result()
        await ScanRepository.store_scan_result(result, is_new=False)  # Update existing scan result

    def get_total_findings(self) -> int:
        """Returns the current total number of findings after processing."""
        return len(self.combined_findings)

    async def _get_scan_result(self) -> ScanResult:
        """Creates a ScanResult object with the current state of processing."""
        scan_result = await ScanRepository.get_scan_result(self.scan_id)
        scan_result.summary = self.summary_result
        scan_result.info_message = "Scan completed"
        scan_result.type = (
            self.detected_type if isinstance(self.detected_type, Profiles) else Profiles.DEFAULT
        )
        scan_result.total_findings = len(self.combined_findings)
        scan_result.findings = self.combined_findings
        scan_result.findings_before_removal = self.findings_before_removal
        return scan_result
