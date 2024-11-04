from typing import Dict, List

from api.v1.helpers.retry_helper import retry_async_operation
from api.v1.schemas.context_scan_schema import FindingList
from common.logger import logger
from common.parse_llm_response import parse_model_response
from common.send_prompt_to_llm import send_prompt_to_llm_async
from config.prompts.duplicate_prompts import DUPLICATE_PROMPT
from config.settings import LLM_MODEL_MEDIUM


async def remove_duplicates(vulns: List[Dict]) -> List[Dict]:
    """
    Sends the new and existing vulnerabilities to the LLM for comparison and returns unique findings.

    Args:
        vulns (List[Dict]): list of all vulnerabilities combined.

    Returns:
        List[Dict]: A list of unique vulnerabilities after LLM removal.
    """

    # Prepare the prompt
    prompt = DUPLICATE_PROMPT.format(vulnerabilities=vulns)
    logger.info(f"Removing duplicates from {len(vulns)} findings...")

    try:
        # Send the prompt to the LLM using retry_async_operation
        llm_response = await retry_async_operation(
            send_prompt_to_llm_async, LLM_MODEL_MEDIUM, prompt
        )

        # Use parse_model_response to handle the LLM response
        parsed_response = parse_model_response(llm_response, FindingList)

        if not isinstance(parsed_response, FindingList):
            raise ValueError("Parsed response is not a FindingList")

        logger.info(f"Total findings after duplicate removal: {len(parsed_response.findings)}")

        return parsed_response.findings

    except Exception as e:
        logger.exception(f"Failed to remove duplicates: {str(e)}")
        logger.warning("Returning original vulnerabilities.")
        return vulns
