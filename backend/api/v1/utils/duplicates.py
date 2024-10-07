import asyncio
import json
from typing import Dict, List

from api.v1.models.scan import Finding
from api.v1.schemas.static_analyzer_schema import TransformedSlitherResult
from common.logger import logger
from common.parse_llm_response import parse_model_response
from common.send_prompt_to_llm import send_prompt_to_llm_async
from config.prompts.duplicate_prompts import DUPLICATE_PROMPT
from config.settings import DELAY, MAX_RETRIES
from pydantic import BaseModel


class FindingList(BaseModel):
    findings: List[Finding]


class CustomJSONEncoder(json.JSONEncoder):
    def default(self, obj):
        if isinstance(obj, (Finding, TransformedSlitherResult)):
            return obj.__dict__
        return super().default(obj)


async def remove_duplicates(vulns: List[Dict], LLM_MODEL: str) -> List[Dict]:
    """
    Sends the new and existing vulnerabilities to the LLM for comparison and returns unique findings.

    Args:
        vulns (List[Dict]): list of all vulnerabilities combined.

    Returns:
        List[Dict]: A list of unique vulnerabilities after LLM removal.
    """

    # Format the vulnerabilities for the prompt using the custom encoder
    formatted_vulns = json.dumps(vulns, indent=2, cls=CustomJSONEncoder)

    # Prepare the prompt
    prompt = DUPLICATE_PROMPT.format(vulnerabilities=formatted_vulns)

    for attempt in range(1, MAX_RETRIES + 1):
        try:
            # Send the prompt to the LLM
            llm_response = await send_prompt_to_llm_async(LLM_MODEL, prompt)

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
