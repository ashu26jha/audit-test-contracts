import json
from typing import List

from api.v1.schemas.context_scan_schema import Finding, FindingList
from common import logger
from common.send_prompt_to_llm import send_prompt_to_llm_async
from config.prompts.mitigation_prompts import MITIGATION_PROMPT
from config.settings import LLM_MODEL_BEST_3


async def mitigate_findings(
    findings: List[Finding],
    flattened_contracts: str,
) -> List[Finding]:
    """
    Analyzes and potentially adjusts severity of findings based on specific criteria.
    Focuses on overflow/underflow, reentrancy, and access control findings.

    Args:
        findings: List of findings to analyze
        flattened_contracts: Contract code for context

    Returns:
        List[Finding]: Findings with potentially adjusted severities, or original findings if validation fails
    """
    logger.info(f"Starting mitigation analysis for {len(findings)} findings...")

    try:
        # Convert findings to JSON string for the prompt
        findings_json = json.dumps([finding.model_dump() for finding in findings])

        # Prepare the mitigation prompt
        mitigation_prompt = MITIGATION_PROMPT.format(
            findings=findings_json,
            flattened_contracts=flattened_contracts,
        )

        # Get response from LLM
        mitigated_response = await send_prompt_to_llm_async(
            LLM_MODEL_BEST_3,
            mitigation_prompt,
            response_model=FindingList,
        )

        # Validate the length of mitigated findings matches input
        if len(mitigated_response.findings) != len(findings):
            logger.warning(
                f"Mitigation response length mismatch. Expected: {len(findings)}, Got: {len(mitigated_response.findings)}. Using original findings."
            )
            return findings

        logger.info(
            f"Mitigation completed successfully for {len(mitigated_response.findings)} findings."
        )
        return mitigated_response.findings

    except Exception as e:
        logger.error(f"Error during findings mitigation: {e}")
        logger.info("Falling back to original findings without mitigation")
        return findings
