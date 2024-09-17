from __future__ import annotations

import json
import re
from typing import List, Optional

from api.v1.prompts.context_scan_prompts import (
    CONTEXT_PROMPT_WITH_SUMMARY,
    CONTEXT_PROMPT_WITHOUT_SUMMARY,
    SYSTEM_PROMPT,
)
from api.v1.schemas.context_scan_exceptions import (
    ContextScanException,
    EmptyResponseError,
    InvalidFormatError,
    InvalidJSONError,
    JSONParsingError,
    NetworkError,
    UnexpectedError,
)
from api.v1.schemas.context_scan_schema import Finding
from common.logger import logger
from common.profiles import Profiles, load_profile
from common.send_prompt_to_LLM import send_prompt_to_llm_async
from config.settings import LLM_MODEL


async def perform_context_scan(
    summary: Optional[str], contracts: str, profile: Profiles = Profiles.NONE
) -> List[Finding]:
    """
    Performs a context scan using an LLM and returns structured findings as a list.

    Args:
        summary: An optional summary to provide context for the LLM prompt.
        contracts: A string containing the contract code to scan.
        profile: The profile to use for the context scan.

    Returns:
        A list of Finding objects representing the scan results.

    Raises:
        Various exceptions for different error conditions.
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
        # Send the prompt to the LLM asynchronously
        message_history = load_profile(profile)
        prediction = await send_prompt_to_llm_async(
            LLM_MODEL, prompt, system_prompt, message_history
        )

        # Ensure the prediction is not None or empty
        if not prediction or not prediction.strip():
            raise EmptyResponseError("LLM response was None or empty.")

        # Use regex to extract JSON content from the response
        json_match = re.search(r"```json\s*(.*?)```", prediction, re.DOTALL)

        if json_match:
            prediction = json_match.group(1).strip()
        else:
            raise InvalidJSONError("No valid JSON content found in the LLM response.")

        # Clean up JSON string if necessary
        if prediction.startswith('"') and prediction.endswith('"'):
            prediction = prediction[1:-1].replace('\\"', '"')

        findings_json = json.loads(prediction)

        # Ensure the parsed response is a list of findings
        if not isinstance(findings_json, list):
            raise InvalidFormatError("Expected the LLM response to be a list of findings.")

        # Convert the JSON response into a list of Finding objects
        findings = [Finding(**finding) for finding in findings_json]

    except ContextScanException:
        raise
    except json.JSONDecodeError as e:
        logger.error(f"JSON Parsing Error: {str(e)}")
        raise JSONParsingError("Failed to parse LLM response as valid JSON.") from e
    except ValueError as e:
        logger.error(f"Value Error: {str(e)}")
        raise InvalidFormatError(str(e)) from e
    except (ConnectionError, TimeoutError) as e:
        logger.error(f"Network Error: {str(e)}")
        raise NetworkError("A network error occurred while processing the response.") from e
    except Exception as e:
        logger.exception(f"Unexpected Error: {str(e)}")
        raise UnexpectedError(f"An unexpected error occurred: {str(e)}") from e

    # Return the list of findings
    return findings
