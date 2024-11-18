import json
from datetime import datetime, timezone
from typing import List
from uuid import UUID

from api.v1.schemas.context_scan_schema import Finding, FindingList, InterestingFindings
from api.v1.services import scan_history_service
from api.v1.services.audit_services.flatten_contracts import flatten_contracts
from common import duplicates, logger
from common.contract_utils import filter_by_contracts
from common.parse_llm_response import parse_model_response
from common.profiles import Profiles
from common.send_prompt_to_llm import send_prompt_to_llm_async
from config.prompts.confidence_sort_prompts import CONFIDENCE_SORT_PROMPT
from config.prompts.shortlist_interesting_findings_prompts import INTERESTING_FINDINGS_PROMPT
from config.settings import LLM_MODEL_BEST, LLM_MODEL_MEDIUM


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

    async def process_results(self, temp_dir: str) -> None:
        """Process results sequentially: filter first, then deduplicate."""
        # First filter findings to reduce the set
        await self._filter_findings()
        await scan_history_service.update_scan_progress(self.scan_id, 95)

        # Then run deduplication on the filtered set
        await self._deduplicate_findings()
        await scan_history_service.update_scan_progress(self.scan_id, 98)

        # Perform confidence scoring
        await self._perform_confidence_scoring(temp_dir)

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

    async def _perform_confidence_scoring(self, temp_dir: str) -> None:
        """
        Performs confidence scoring on the findings.
            1. Sends to LLM to get interesting findings
            2. Sends to LLM to score confidence of interesting findings
            3. Add a tag to most confident finding
        """
        summary_of_project = self.summary_result
        findings = self.dedup_findings
        selected_contracts = self.selected_contracts

        # Set confidence to 0 if present
        for finding in findings:
            finding.Confidence = 0

        self.dedup_findings = findings
        flattened_contracts = await flatten_contracts(selected_contracts, temp_dir)

        interesting_findings_prompt = INTERESTING_FINDINGS_PROMPT.format(
            summary=summary_of_project, findings=findings
        )

        try:
            # Get raw response from LLM for interesting findings
            raw_response = await send_prompt_to_llm_async(
                model_type=LLM_MODEL_MEDIUM,
                user_input=interesting_findings_prompt,
                response_model=InterestingFindings,
            )

            interesting_findings_indexes = raw_response.interesting_findings

            findings_to_send_confidence_sort = []
            for finding_index in interesting_findings_indexes:
                if finding_index < len(findings):
                    findings_to_send_confidence_sort.append(findings[finding_index])
                else:
                    logger.error(f"Finding index out of bounds: {finding_index}")

            # Convert findings to JSON string for the prompt
            findings_json = json.dumps(
                [finding.dict() for finding in findings_to_send_confidence_sort]
            )

            # Prepare the confidence scoring prompt
            confidence_sort_prompt = CONFIDENCE_SORT_PROMPT.format(
                contract_summary=summary_of_project,
                flattened_contracts=flattened_contracts,
                findings=findings_json,
            )

            try:
                # Get raw response from LLM for confidence scoring
                raw_response = await send_prompt_to_llm_async(
                    LLM_MODEL_BEST,
                    confidence_sort_prompt,
                )

                # Parse into the model
                parsed_response = parse_model_response(raw_response, FindingList)

                final_findings = []
                i = 0

                # Logic to add confidence findings and non confidence findings
                # @dev Iterates over the deduplicated findings, if index was in interesting findings,
                # add the confidence score from the parsed response, else add the original finding
                for index, finding in enumerate(self.dedup_findings):
                    if index in interesting_findings_indexes:
                        if i < len(parsed_response.findings):
                            final_findings.append(parsed_response.findings[i])
                            i += 1
                    else:
                        final_findings.append(finding)

                self.dedup_findings = final_findings

            except Exception as e:
                logger.error(f"Error during confidence scoring: {e}")
                pass

        except Exception as e:
            logger.error(f"Error getting interesting findings: {e}")
            pass

    # Getters

    def get_total_findings(self) -> int:
        return self.total_findings_after_dedup

    def get_deduplicated_findings(self) -> List[Finding]:
        return self.dedup_findings
