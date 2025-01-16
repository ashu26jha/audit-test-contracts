import json
from typing import List

from api.v1.detectors.context_scan.schema import FindingList
from config.prompts.mitigation_prompts import MITIGATION_PROMPT
from config.settings import LLM_UTILITY
from core.llm.send_prompt_to_llm import send_prompt_to_llm_async
from core.models.scan import Finding
from core.utils.logger import logger


async def mitigate_findings_async(
    findings: List[Finding],
    flattened_contracts: str,
) -> List[Finding]:
    """
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

        # Send to LLM
        mitigated_response = await send_prompt_to_llm_async(
            LLM_UTILITY,
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
