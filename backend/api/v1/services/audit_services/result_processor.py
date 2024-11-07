from datetime import datetime, timezone
from typing import List
from uuid import UUID

from api.v1.schemas.context_scan_schema import Finding
from api.v1.services import scan_history_service
from common import duplicates, logger
from common.contract_utils import filter_by_contracts
from common.profiles import Profiles


class ResultProcessor:
    def __init__(
        self,
        scan_id: UUID,
        user_id: str,
        combined_findings: List[Finding],
        selected_contracts: List[str],
        summary_result: str,
        detected_type: Profiles,
    ):
        self.scan_id = scan_id
        self.user_id = user_id
        self.combined_findings = combined_findings
        self.selected_contracts = selected_contracts
        self.summary_result = summary_result
        self.detected_type = detected_type
        self.dedup_findings: List[Finding] = []
        self.total_findings_after_dedup: int = 0

    async def process_results(self) -> None:
        """Process results sequentially: filter first, then deduplicate."""
        # First filter findings to reduce the set
        await self._filter_findings()
        await scan_history_service.update_scan_progress(self.scan_id, 95)

        # Then run deduplication on the filtered set
        await self._deduplicate_findings()
        await scan_history_service.update_scan_progress(self.scan_id, 98)

        # Final update
        await self._update_scan_result()

        # Update progress to 100% when everything is done
        scan = await scan_history_service.get_scan(self.scan_id)
        if scan:
            scan.progress = 100.0
            await scan.save()

    async def _filter_findings(self) -> None:
        """
        Filters findings to include only those in selected contracts.
        """
        filtered_findings = filter_by_contracts(
            self.combined_findings, self.selected_contracts, contract_field="Contracts"
        )

        removed_count = len(self.combined_findings) - len(filtered_findings)
        logger.info(f"Filtered out {removed_count} findings that didn't match selected contracts")

        self.combined_findings = filtered_findings

    async def _deduplicate_findings(self) -> None:
        """
        Deduplicates findings to remove any duplicates.
        """
        self.dedup_findings = await duplicates.remove_duplicates(self.combined_findings)
        self.total_findings_after_dedup = len(self.dedup_findings)

    async def _update_scan_result(self) -> None:
        """
        Updates the scan result in the database with the processed findings.
        """
        scan_result = await scan_history_service.get_scan_result(self.scan_id)
        scan_result.summary = self.summary_result
        scan_result.info_message = "Scan completed"
        scan_result.type = (
            self.detected_type if isinstance(self.detected_type, Profiles) else Profiles.DEFAULT
        )
        scan_result.total_findings = self.total_findings_after_dedup
        scan_result.findings = self.dedup_findings
        scan_result.findings_before_removal = self.combined_findings
        scan_result.completedAt = datetime.now(timezone.utc)
        await scan_result.save()

    def get_total_findings(self) -> int:
        return self.total_findings_after_dedup

    def get_deduplicated_findings(self) -> List[Finding]:
        return self.dedup_findings
