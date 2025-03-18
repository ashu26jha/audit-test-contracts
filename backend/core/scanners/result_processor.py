import gc
from typing import Dict, List, Tuple
from uuid import UUID

from typing_extensions import final

from api.v1.common import contract_utils
from api.v1.utilities.critics.service import CriticService
from core.db.repositories.scan import ScanRepository
from core.models.scan import Finding, Invariant, ScanResult
from core.schemas.scan_schema import Detectors
from core.utils import logger
from core.utils.profiles import Profiles


class BaseResultsProcessor:
    def __init__(
        self,
        scan_id: UUID,
        user_id: str,
        contract_files: List[str],
        combined_findings: List[Finding],
        summary_result: str,
        detected_type: Profiles,
        invariants: List[Invariant],
        contract_contents: Dict[str, str],
    ):
        self.scan_id = scan_id
        self.user_id = user_id
        self.combined_findings: List[Finding] = []  # Initialize empty
        self.findings_before_removal = combined_findings  # Store initial findings
        self.selected_contracts = contract_files
        self.contract_contents = contract_contents or {}  # Store contract contents dictionary
        self.summary_result = summary_result
        self.detected_type = detected_type
        self.invariants = invariants

    @final
    async def process_results(self) -> int:
        """
        Process scan results through the complete critic phase.

        The critic phase consists of sequential steps:
        1. Filter findings to match selected contracts
        2. Separate static analyzer findings
        3. Mitigate non-static findings edge cases(adjust severity, remove false positives)
        4. Validate non-static findings (filter out low-quality findings)
        5. Enrich findings (improve descriptions and severity based on critical analysis)
        6. Merge static analyzer findings back with processed findings
        7. Deduplicate all findings (remove redundant findings)

        Each step uses batch processing for efficiency, with deduplication
        specifically using hierarchical processing to compare findings across batches.

        Returns:
            Number of findings after processing
        """

        await ScanRepository.update_scan_progress(self.scan_id, 80)

        # 1. Filter findings to ensure they all belong to the selected contracts
        initial_count = len(self.findings_before_removal)
        self.findings_before_removal = contract_utils.filter_by_contracts(
            self.findings_before_removal, self.selected_contracts, contract_field="Contracts"
        )
        logger.logger.info(
            f"[ResultProcessor] Filtered {initial_count - len(self.findings_before_removal)} findings that didn't match selected contracts"
        )

        # 2. Separate static analyzer findings from other findings
        non_static_findings, static_findings = self._filter_static_analyzer_findings(
            self.findings_before_removal
        )
        await ScanRepository.update_scan_progress(self.scan_id, 82)

        # 3. Perform mitigation on non-static findings
        processed_findings = await CriticService.run_mitigation(
            findings=non_static_findings,
            contract_contents=self.contract_contents,
        )
        await ScanRepository.update_scan_progress(self.scan_id, 85)

        # 4. Perform validation with non-static findings and contract contents
        processed_findings = await CriticService.run_validation(
            findings=processed_findings, contract_contents=self.contract_contents
        )
        await ScanRepository.update_scan_progress(self.scan_id, 92)

        # 5. Enrich findings' descriptions and recommendations based on critic analysis
        processed_findings = await CriticService.enrich_findings(
            findings=processed_findings, contract_contents=self.contract_contents
        )
        await ScanRepository.update_scan_progress(self.scan_id, 97)

        # 6. Merge static analyzer findings back with processed findings
        self.combined_findings = self._merge_findings(processed_findings, static_findings)

        # 7. Perform deduplication on all findings
        self.combined_findings = await CriticService.run_deduplication(self.combined_findings)
        await ScanRepository.update_scan_progress(self.scan_id, 100)

        # Clear memory
        self.contract_contents = None
        gc.collect()

        # 8. Update scan result in database
        result = await self._get_scan_result()
        await ScanRepository.store_scan_result(result, is_new=False)  # Update existing scan result

        return len(self.combined_findings)

    def _filter_static_analyzer_findings(
        self, findings: List[Finding]
    ) -> Tuple[List[Finding], List[Finding]]:
        """
        Separates static analyzer findings from other findings.

        Args:
            findings: List of all findings to filter

        Returns:
            Tuple containing (non_static_findings, static_findings)
        """
        static_findings = []
        non_static_findings = []

        for finding in findings:
            if finding.Detector == Detectors.STATIC_ANALYZER.value:
                static_findings.append(finding)
            else:
                non_static_findings.append(finding)

        logger.logger.info(
            f"[ResultProcessor] Separated {len(static_findings)} static analyzer findings from {len(non_static_findings)} other findings"
        )

        return non_static_findings, static_findings

    def _merge_findings(
        self, processed_findings: List[Finding], static_findings: List[Finding]
    ) -> List[Finding]:
        """
        Merges processed findings with static analyzer findings.

        Args:
            processed_findings: Findings that have gone through mitigation and validation
            static_findings: Static analyzer findings that were processed separately

        Returns:
            Combined list of all findings
        """
        merged_findings = processed_findings + static_findings
        logger.logger.info(
            f"[ResultProcessor] Merged {len(processed_findings)} processed findings with {len(static_findings)} static analyzer findings"
        )

        return merged_findings

    @final
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
        scan_result.invariants = self.invariants
        return scan_result
