import json
from typing import List, Set

from api.v1.detectors.context_scan.schema import FindingList, InterestingFindings
from config.prompts.confidence_sort_prompts import CONFIDENCE_SORT_PROMPT
from config.prompts.shortlist_interesting_findings_prompts import INTERESTING_FINDINGS_PROMPT
from config.settings import LLM_UTILITY
from core.llm.send_prompt_to_llm import send_prompt_to_llm_async
from core.models.scan import Finding
from core.utils.logger import logger


async def confidence_scoring_async(
    findings: List[Finding],
    summary_of_project: str,
    flattened_contracts: str,
) -> List[Finding]:
    """
    Implementation Notes:
    - For >5 findings, uses LLM to select most interesting ones
    - Maintains original findings order
    - Sets confidence=0 for non-selected findings
    - Falls back to original findings on any error
    """
    logger.info("Starting confidence scoring on deduplicated findings...")

    try:
        # Set initial confidence to 0
        for finding in findings:
            finding.Confidence = 0

        # Get interesting findings if needed
        findings_to_send_confidence_sort = await _get_interesting_findings(
            findings, summary_of_project
        )

        # Get confidence scores
        final_findings = await _get_confidence_scores(
            findings,
            findings_to_send_confidence_sort,
            summary_of_project,
            flattened_contracts,
        )

        logger.info("Confidence scoring completed successfully.")
        return final_findings

    except Exception as e:
        logger.error(f"Error in confidence scoring process: {e}")
        return findings


async def _get_interesting_findings(
    findings: List[Finding], summary_of_project: str
) -> List[Finding]:
    """Get most interesting findings for larger sets."""
    findings_to_send_confidence_sort = []
    interesting_findings_indexes: List[int] = []

    # If 5 or fewer findings, skip interesting findings selection
    if len(findings) <= 5:
        logger.info(f"Only {len(findings)} findings, skipping interesting findings selection")
        return findings

    try:
        # Cache model dumps for findings
        findings_dumps = [finding.model_dump() for finding in findings]

        # Get interesting findings for larger sets
        interesting_findings_prompt = INTERESTING_FINDINGS_PROMPT.format(
            total_findings=len(findings), summary=summary_of_project, findings=findings_dumps
        )

        # Get raw response from LLM for interesting findings
        raw_response = await send_prompt_to_llm_async(
            model_type=LLM_UTILITY,
            user_input=interesting_findings_prompt,
            response_model=InterestingFindings,
        )

        interesting_findings_indexes = raw_response.interesting_findings

        for finding_index in interesting_findings_indexes:
            if finding_index < len(findings):
                findings_to_send_confidence_sort.append(findings[finding_index])
            else:
                logger.error(f"Finding index out of bounds: {finding_index}")

    except Exception as e:
        logger.error(f"Error getting interesting findings: {e}")
        findings_to_send_confidence_sort = findings
        interesting_findings_indexes = []

    return findings_to_send_confidence_sort


async def _get_confidence_scores(
    original_findings: List[Finding],
    findings_to_score: List[Finding],
    summary_of_project: str,
    flattened_contracts: str,
) -> List[Finding]:
    """Get confidence scores for the selected findings."""
    try:
        # Cache model dumps for findings
        findings_dumps = {id(finding): finding.model_dump() for finding in findings_to_score}
        findings_json = json.dumps([findings_dumps[id(f)] for f in findings_to_score])

        # Create a set for O(1) lookups
        findings_to_score_set: Set[Finding] = set(findings_to_score)

        # Prepare the confidence scoring prompt
        confidence_sort_prompt = CONFIDENCE_SORT_PROMPT.format(
            contract_summary=summary_of_project,
            flattened_contracts=flattened_contracts,
            findings=findings_json,
        )

        # Get raw response from LLM for confidence scoring
        confidence_response = await send_prompt_to_llm_async(
            LLM_UTILITY,
            confidence_sort_prompt,
            response_model=FindingList,
        )

        final_findings = []
        i = 0

        # Logic to add confidence findings and non confidence findings
        for finding in original_findings:
            if finding in findings_to_score_set and i < len(confidence_response.findings):
                final_findings.append(confidence_response.findings[i])
                i += 1
            else:
                final_findings.append(finding)

        return final_findings

    except Exception as e:
        logger.error(f"Error during confidence scoring: {e}")
        logger.info("Falling back to original findings without confidence scoring")
        return original_findings
