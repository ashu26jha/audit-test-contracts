import json
from typing import List

from api.v1.schemas.context_scan_schema import Finding, FindingList, InterestingFindings
from common import logger
from common.send_prompt_to_llm import send_prompt_to_llm_async
from config.prompts.confidence_sort_prompts import CONFIDENCE_SORT_PROMPT
from config.prompts.shortlist_interesting_findings_prompts import INTERESTING_FINDINGS_PROMPT
from config.settings import LLM_MODEL_BEST_3


async def confidence_scoring(
    findings: List[Finding],
    summary_of_project: str,
    flattened_contracts: str,
) -> List[Finding]:
    """
    Performs confidence scoring on the findings.
        1. Sends to LLM to get interesting findings (if more than 5 findings)
        2. Sends to LLM to score confidence of interesting findings
        3. Add a tag to most confident finding
    If any step fails, returns original findings.

    Args:
        findings: List of findings to score
        summary_of_project: Project summary for context
        flattened_contracts: Flattened contracts for context

    Returns:
        List[Finding]: Findings with confidence scores, or original findings if scoring fails
    """
    logger.info("Starting confidence scoring on deduplicated findings...")

    try:
        # Set confidence to 0 if present
        for finding in findings:
            finding.Confidence = 0

        findings_to_send_confidence_sort = []
        interesting_findings_indexes: List[int] = []

        # If 5 or fewer findings, skip interesting findings selection
        if len(findings) <= 5:
            logger.info(f"Only {len(findings)} findings, skipping interesting findings selection")
            findings_to_send_confidence_sort = findings
        else:
            try:
                # Get interesting findings for larger sets
                interesting_findings_prompt = INTERESTING_FINDINGS_PROMPT.format(
                    total_findings=len(findings), summary=summary_of_project, findings=findings
                )

                # Get raw response from LLM for interesting findings
                raw_response = await send_prompt_to_llm_async(
                    model_type=LLM_MODEL_BEST_3,
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

        try:
            # Convert findings to JSON string for the prompt
            findings_json = json.dumps(
                [finding.model_dump() for finding in findings_to_send_confidence_sort]
            )

            # Prepare the confidence scoring prompt
            confidence_sort_prompt = CONFIDENCE_SORT_PROMPT.format(
                contract_summary=summary_of_project,
                flattened_contracts=flattened_contracts,
                findings=findings_json,
            )

            # Get raw response from LLM for confidence scoring
            confidence_response = await send_prompt_to_llm_async(
                LLM_MODEL_BEST_3,
                confidence_sort_prompt,
                response_model=FindingList,
            )

            final_findings = []
            i = 0

            # Logic to add confidence findings and non confidence findings
            for index, finding in enumerate(findings):
                if index in interesting_findings_indexes and i < len(confidence_response.findings):
                    final_findings.append(confidence_response.findings[i])
                    i += 1
                else:
                    final_findings.append(finding)

            return final_findings

        except Exception as e:
            logger.error(f"Error during confidence scoring: {e}")
            logger.info("Falling back to original findings without confidence scoring")
            return findings

    except Exception as e:
        logger.error(f"Error in confidence scoring process: {e}")
        return findings
