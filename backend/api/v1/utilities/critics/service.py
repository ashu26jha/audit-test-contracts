from typing import Dict, List

from langfuse.decorators import observe

from api.v1.utilities.critics.helpers.duplicates import remove_duplicates_batched
from api.v1.utilities.critics.helpers.mitigation import mitigate_findings_async
from api.v1.utilities.critics.helpers.validation import validate_findings_batched
from core.models.scan import Finding


class CriticService:
    """
    Service for processing findings through various critic operations.

    The critic phase consists of three main operations:
    1. Mitigation: Adjusts severity ratings and removes false positives
    2. Validation: Scores findings on exploitability, impact, and confidence
    3. Deduplication: Removes duplicate findings
    4. Severity Adjustment: Adjusts severity ratings

    Each operation uses batch processing for efficiency, with deduplication
    specifically using hierarchical batch processing to compare findings
    across batches.
    """

    @staticmethod
    async def run_deduplication(findings: List[Finding]) -> List[Finding]:
        """
        Remove duplicate findings using hierarchical batch processing.

        This operation uses hierarchical processing because deduplication requires
        comparing findings against each other across all batches to identify duplicates.

        Args:
            findings: List of findings to deduplicate

        Returns:
            List of deduplicated findings
        """
        return await remove_duplicates_batched(findings)

    @staticmethod
    async def run_validation(
        findings: List[Finding], contract_contents: Dict[str, str]
    ) -> List[Finding]:
        """
        Validate and score findings using contract-based groups.

        Args:
            findings: List of findings to validate
            contract_contents: Flattened contract code for context

        Returns:
            List of validated findings with low-quality findings removed
        """
        return await validate_findings_batched(
            findings=findings, contract_contents=contract_contents
        )

    @staticmethod
    async def run_mitigation(
        findings: List[Finding], contract_contents: Dict[str, str]
    ) -> List[Finding]:
        """
        Mitigate findings using batch processing.

        This operation processes each finding independently, adjusting severity
        ratings and optionally removing false positives based on contract context.

        Args:
            findings: List of findings to mitigate
            contract_contents: Flattened contract code for context

        Returns:
            List of mitigated findings with false positives removed
        """
        return await mitigate_findings_async(findings, contract_contents)

    @staticmethod
    @observe(name="[CRITICS] run full critic phase")
    async def run_full_critic_phase(
        findings: List[Finding], contract_contents: Dict[str, str]
    ) -> List[Finding]:
        """
        Run a full critic phase on a list of security findings.
        """

        mitigated_findings = await CriticService.run_mitigation(
            findings=findings, contract_contents=contract_contents
        )
        validated_findings = await CriticService.run_validation(
            findings=mitigated_findings, contract_contents=contract_contents
        )
        deduplicated_findings = await CriticService.run_deduplication(validated_findings)

        return deduplicated_findings
