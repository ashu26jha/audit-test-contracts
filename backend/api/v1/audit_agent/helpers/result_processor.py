import asyncio
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
        self.combined_findings = combined_findings
        self.selected_contracts = context.contract_files
        self.flattened_contracts = flattened_contracts
        self.summary_result = summary_result
        self.detected_type = detected_type
        self.dedup_findings: List[Finding] = []
        self.total_findings_after_dedup: int = 0

    async def process_results(self) -> None:
        """Process results sequentially: filter, deduplicate, mitigate, then confidence score."""
        # Filter findings to ensure they all belong to the selected contracts
        await self._filter_findings()
        await ScanRepository.update_scan_progress(self.scan_id, 80)

        await asyncio.sleep(1)  # Brief pause to let CPU settle

        # Perform deduplication
        await self._deduplicate_findings()
        await ScanRepository.update_scan_progress(self.scan_id, 88)

        await asyncio.sleep(1)  # Brief pause to let CPU settle

        # Process mitigation and confidence scoring in parallel
        await self._process_parallel_tasks()
        self.flattened_contracts = None
        gc.collect()
        await ScanRepository.update_scan_progress(self.scan_id, 100)

        # Final update
        result = await self._get_scan_result()
        is_new = False  # Update an existing scan result
        await ScanRepository.store_scan_result(result, is_new)

    async def _get_scan_result(self) -> ScanResult:
        """
        Creates a ScanResult object with the current state of processing.
        """
        scan_result = await ScanRepository.get_scan_result(self.scan_id)
        scan_result.summary = self.summary_result
        scan_result.info_message = "Scan completed"
        scan_result.type = (
            self.detected_type if isinstance(self.detected_type, Profiles) else Profiles.DEFAULT
        )
        scan_result.total_findings = self.total_findings_after_dedup
        scan_result.findings = self.dedup_findings
        scan_result.findings_before_removal = self.combined_findings
        return scan_result

    async def _filter_findings(self) -> None:
        """
        Filters findings to include only those in selected contracts.
        """
        filtered_findings = contract_utils.filter_by_contracts(
            self.combined_findings, self.selected_contracts, contract_field="Contracts"
        )

        removed_count = len(self.combined_findings) - len(filtered_findings)
        logger.logger.info(
            f"Filtered out {removed_count} findings that didn't match selected contracts"
        )

        self.combined_findings = filtered_findings

    async def _deduplicate_findings(self) -> None:
        """
        Deduplicates findings to remove any duplicates.
        """
        self.dedup_findings = await CriticService.remove_duplicates(self.combined_findings)
        self.total_findings_after_dedup = len(self.dedup_findings)
        self.combined_findings = None
        gc.collect()

    async def _process_parallel_tasks(self) -> None:
        """
        Process mitigation and confidence scoring in parallel since they don't depend on each other.
        """
        # Create tasks for parallel processing
        tasks = [
            self._perform_confidence_scoring(),
            self._mitigate_findings(),
        ]

        # Wait for both tasks to complete
        results = await asyncio.gather(*tasks)

        # Combine results - take the confidence scores from the first task
        # and severity adjustments from the second task
        confidence_findings, mitigated_findings = results

        # Update findings with both confidence scores and mitigated severities
        for i, finding in enumerate(self.dedup_findings):
            if i < len(confidence_findings):
                finding.Confidence = confidence_findings[i].Confidence
            if i < len(mitigated_findings):
                finding.Severity = mitigated_findings[i].Severity

    async def _perform_confidence_scoring(self) -> List[Finding]:
        """
        Performs confidence scoring on the findings using the confidence scoring helper.
        If any step fails, the process continues with original findings.
        """
        return await CriticService.confidence_scoring(
            findings=self.dedup_findings,
            summary_of_project=self.summary_result,
            flattened_contracts=self.flattened_contracts,
        )

    async def _mitigate_findings(self) -> List[Finding]:
        """
        Analyzes and potentially adjusts severity of specific finding types.
        If any step fails, the process continues with original findings.
        """
        return await CriticService.mitigate_findings(
            findings=self.dedup_findings,
            flattened_contracts=self.flattened_contracts,
        )

    def get_total_findings(self) -> int:
        return self.total_findings_after_dedup
