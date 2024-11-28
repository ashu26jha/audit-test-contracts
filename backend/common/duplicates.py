import json
from typing import List

from api.v1.schemas.context_scan_schema import Finding, FindingList
from common.logger import logger
from common.send_prompt_to_llm import send_prompt_to_llm_async
from config.prompts.duplicate_prompts import DUPLICATE_PROMPT
from config.settings import LLM_MODEL_BEST_3


async def remove_duplicates(vulns: List[Finding]) -> List[Finding]:

    try:
        if not vulns:
            return []

        # Prepare the prompt
        vulns_json = {"findings": [finding.model_dump() for finding in vulns]}

        prompt = DUPLICATE_PROMPT.format(vulnerabilities=json.dumps(vulns_json, indent=2))
        logger.info(f"Removing duplicates from {len(vulns)} findings...")

        # Send the prompt to LLM
        llm_response: FindingList = await send_prompt_to_llm_async(
            model_type=LLM_MODEL_BEST_3,
            user_input=prompt,
            response_model=FindingList,
        )

        logger.info(f"Total findings after duplicate removal: {len(llm_response.findings)}")

        return llm_response.findings

    except Exception as e:
        logger.exception(f"Failed to remove duplicates: {str(e)}")
        logger.warning("Returning original vulnerabilities.")
        return vulns
