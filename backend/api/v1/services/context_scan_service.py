from __future__ import annotations

import json
import re
from typing import Any, Dict, Optional

from api.v1.prompts.context_scan_prompts import (
    CONTEXT_PROMPT_WITH_SUMMARY,
    CONTEXT_PROMPT_WITHOUT_SUMMARY,
    SYSTEM_PROMPT,
)
from api.v1.schemas.context_scan_schema import Finding
from common.logger import logger
from common.profiles import Profiles, load_profile
from common.send_prompt_to_LLM import send_prompt_to_llm_async
from config.settings import LLM_MODEL


async def perform_context_scan(
    summary: Optional[str], contracts: str, profile: Profiles = Profiles.NONE
) -> Dict[str, Any]:
    """
    Performs a context scan using an LLM and returns structured findings in a dict.

    Args:
        summary: An optional summary to provide context for the LLM prompt.
        contracts: A string containing the contract code to scan.

    Returns:
        A dictionary containing the summary, contracts, and an array of findings.
    """

    # Determine if system prompt should be used
    system_prompt = SYSTEM_PROMPT if profile != Profiles.NONE else None

    # Select the appropriate prompt based on the presence of a summary
    prompt = (
        CONTEXT_PROMPT_WITH_SUMMARY.format(summary=summary, flattened_contracts=contracts)
        if summary
        else CONTEXT_PROMPT_WITHOUT_SUMMARY.format(flattened_contracts=contracts)
    )

    try:
        # Send the prompt to the LLM asynchronously and log the raw response
        message_history = load_profile(profile)
        print(message_history)
        prediction = await send_prompt_to_llm_async(
            LLM_MODEL, prompt, system_prompt, message_history
        )
        # Ensure the prediction is not None or empty
        if not prediction or not prediction.strip():
            raise ValueError("LLM response was None or empty.")

        # Use regex to extract the content between the triple backticks ```json ... ```
        json_match = re.search(r"```json(.*?)```", prediction, re.DOTALL)

        if json_match:
            prediction = json_match.group(1).strip()
        else:
            raise ValueError("No valid JSON content found in the LLM response.")

        if prediction.startswith('"') and prediction.endswith('"'):
            prediction = prediction[1:-1].replace('\\"', '"')

        findings_json = json.loads(prediction)

        # Ensure the parsed response is a list of findings
        if not isinstance(findings_json, list):
            raise ValueError("Expected the LLM response to be a list of findings.")

        # Convert the JSON response into a list of Finding objects
        findings = [Finding(**finding) for finding in findings_json]

    except json.JSONDecodeError as e:
        logger.error(f"Failed to decode JSON: {e}")
        findings = [
            {
                "Issue": "Parsing Error",
                "Severity": "Error",
                "Contracts": [],
                "Description": "Failed to parse LLM response as valid JSON.",
            }
        ]

    except ValueError as e:
        logger.error(f"Error in LLM response: {e}")
        findings = [
            {
                "Issue": "Response Error",
                "Severity": "Error",
                "Contracts": [],
                "Description": str(e),
            }
        ]

    except (ConnectionError, TimeoutError) as e:
        logger.error(f"Network-related error: {e}")
        findings = [
            {
                "Issue": "Network Error",
                "Severity": "Error",
                "Contracts": [],
                "Description": "A network error occurred while processing the response.",
            }
        ]

    except Exception as e:
        logger.error(f"Unexpected error: {e}")
        findings = [
            {
                "Issue": "Unexpected Error",
                "Severity": "Error",
                "Contracts": [],
                "Description": f"An unexpected error occurred: {e}",
            }
        ]

    # Return the structured result
    return {"summary": summary, "contracts": contracts, "scan_result": findings}
