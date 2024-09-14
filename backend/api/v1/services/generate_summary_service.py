import json
import re
from typing import Dict

from api.v1.prompts.generate_summary_prompts import SUMMARY_PROMPT
from common import logger
from common.send_prompt_to_LLM import send_prompt_to_llm_async
from config.settings import LLM_MODEL_SUMMARY


async def generate_summary(contracts: str) -> Dict[str, str]:
    """
    Generates a summary and type for the given contract text.

    Args:
        contract: The contract text to summarize.

    Returns:
        A dictionary containing 'summary' and 'type'.

    Raises:
        Exception: If an error occurs during processing.
    """

    # Concatenate the prompt with the contract
    prompt = SUMMARY_PROMPT.format(contracts=contracts)

    try:
        llm_response = await send_prompt_to_llm_async(LLM_MODEL_SUMMARY, prompt)

        # Extract JSON content from the response
        json_match = re.search(r"```json\s*(.*?)```", llm_response, re.DOTALL)
        if json_match:
            json_content = json_match.group(1).strip()

            # Parse the JSON content
            data = json.loads(json_content)
            summary = data.get("summary", "")
            type = data.get("type", "")

            return {"summary": summary, "type": type}
        else:
            logger.error("Failed to extract JSON content from LLM response.")
            raise Exception("Failed to extract summary from LLM response.")

    except Exception as e:
        logger.error(f"Error in generate_summary: {str(e)}")
        raise
