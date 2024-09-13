from api.v1.schemas.context_scan_schema import Finding
from common.profiles import Profiles
from config.settings import LLM_MODEL
from common.logger import logger
from typing import Optional, Dict, Any
from common.send_prompt_to_LLM import send_prompt_to_llm_async
import json
from api.v1.prompts.context_scan_prompts import (
    context_prompt_with_summary,
    context_prompt_without_summary,
)


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

    # Select the appropriate prompt based on the presence of a summary
    prompt = (
        context_prompt_with_summary.format(
            summary=summary, flattened_contracts=contracts
        )
        if summary
        else context_prompt_without_summary.format(flattened_contracts=contracts)
    )

    try:
        # Send the prompt to the LLM asynchronously and log the raw response
        prediction = await send_prompt_to_llm_async(prompt, LLM_MODEL, profile)

        # Ensure the prediction is not None or empty
        if not prediction or not prediction.strip():
            raise ValueError("LLM response was None or empty.")

        # Clean the prediction for valid JSON
        prediction = (
            prediction.strip().replace("```json", "").replace("```", "").strip()
        )

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

    except Exception as e:
        logger.error(f"Unexpected error: {e}")
        findings = [
            {
                "Issue": "Unexpected Error",
                "Severity": "Error",
                "Contracts": [],
                "Description": "An unexpected error occurred while processing the response.",
            }
        ]

    # Return the structured result
    return {"summary": summary, "contracts": contracts, "scan_result": findings}
