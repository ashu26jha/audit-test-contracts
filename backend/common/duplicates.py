import asyncio
from typing import Dict, List

from api.v1.schemas.context_scan_schema import FindingList
from common.logger import logger
from common.parse_llm_response import parse_model_response
from common.send_prompt_to_llm import send_prompt_to_llm_async
from config.prompts.duplicate_prompts import DUPLICATE_PROMPT
from config.settings import DELAY, LLM_MODEL_MEDIUM, MAX_RETRIES


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

    for attempt in range(1, MAX_RETRIES + 1):
        try:
            # Send the prompt to the LLM
            llm_response = await send_prompt_to_llm_async(LLM_MODEL_MEDIUM, prompt)

            # Use parse_model_response to handle the LLM response
            parsed_response = parse_model_response(llm_response, FindingList)

            if not isinstance(parsed_response, FindingList):
                raise ValueError("Parsed response is not a FindingList")

            return parsed_response.findings

        except Exception as e:
            logger.error(f"Attempt {attempt} failed: {str(e)}")

        if attempt < MAX_RETRIES:
            logger.info(f"Retrying in {DELAY} seconds...")
            await asyncio.sleep(DELAY)
        else:
            logger.warning("Max retries reached. Returning original vulnerabilities.")
            return vulns

    return vulns
