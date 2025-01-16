import json
from typing import List

from api.v1.detectors.context_scan.schema import FindingList
from config.prompts.duplicate_prompts import DUPLICATE_PROMPT
from config.settings import LLM_UTILITY
from core.llm.send_prompt_to_llm import send_prompt_to_llm_async
from core.models.scan import Finding
from core.utils.logger import logger


async def remove_duplicates_async(findings: List[Finding]) -> List[Finding]:
    """Remove duplicate findings using LLM."""

    logger.info(f"Removing duplicates from {len(findings)} findings...")

    try:

        if not findings:
            return []

        # Format findings for LLM
        formatted_findings = json.dumps([finding.model_dump() for finding in findings])
        prompt = DUPLICATE_PROMPT.format(vulnerabilities=formatted_findings)

        # Send the prompt to LLM
        llm_response: FindingList = await send_prompt_to_llm_async(
            LLM_UTILITY,
            prompt,
            response_model=FindingList,
        )

        if not llm_response or not llm_response.findings:
            logger.warning("No findings returned from LLM, returning original findings")
            return findings

        logger.info(f"Total findings after duplicate removal: {len(llm_response.findings)}")
        return llm_response.findings

    except Exception as e:
        logger.exception(f"Failed to remove duplicates: {str(e)}")
        logger.warning("Returning original vulnerabilities.")
        return findings
