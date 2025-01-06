import json
from typing import List

from api.v1.detectors.context_scan.schema import FindingList
from config.prompts.duplicate_prompts import DUPLICATE_PROMPT
from config.settings import LLM_UTILITY
from core.llm.send_prompt_to_llm import send_prompt_to_llm_async
from core.models.scan import Finding
from core.utils.logger import logger


async def remove_duplicates_async(vulns: List[Finding]) -> List[Finding]:
    """
    Returns:
        List[Finding]: Findings with duplicates removed, or original findings if deduplication fails
    """
    try:
        if not vulns:
            return []

        # Cache model dumps to avoid redundant serialization
        findings_dumps = {id(finding): finding.model_dump() for finding in vulns}
        vulns_json = {"findings": [findings_dumps[id(f)] for f in vulns]}

        prompt = DUPLICATE_PROMPT.format(vulnerabilities=json.dumps(vulns_json, indent=2))
        logger.info(f"Removing duplicates from {len(vulns)} findings...")

        # Send the prompt to LLM
        llm_response: FindingList = await send_prompt_to_llm_async(
            model_type=LLM_UTILITY,
            user_input=prompt,
            response_model=FindingList,
        )

        logger.info(f"Total findings after duplicate removal: {len(llm_response.findings)}")

        return llm_response.findings

    except Exception as e:
        logger.exception(f"Failed to remove duplicates: {str(e)}")
        logger.warning("Returning original vulnerabilities.")
        return vulns
