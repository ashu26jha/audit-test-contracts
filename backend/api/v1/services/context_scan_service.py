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

        # Try to extract JSON content from the response
        json_matches = re.findall(r"```json\s*(.*?)```", prediction, re.DOTALL)

        if not json_matches:
            logger.warning("No valid JSON content found in the LLM response.")
            # Attempt to fix common JSON issues
            cleaned_prediction = _clean_invalid_json(prediction)
            try:
                findings_json = json.loads(cleaned_prediction)
            except json.JSONDecodeError as e:
                logger.error(f"JSON Parsing Error after cleaning: {str(e)}")
                raise JSONParsingError("Failed to parse LLM response as valid JSON.") from e
            # Ensure the parsed response is a list of findings
            if not isinstance(findings_json, list):
                raise InvalidFormatError("Expected the LLM response to be a list of findings.")
            findings = [Finding(**finding) for finding in findings_json]
        else:
            # Attempt to parse each JSON block
            findings = []
            for json_str in json_matches:
                try:
                    # Clean the JSON string
                    json_str = json_str.strip()
                    if json_str.startswith('"') and json_str.endswith('"'):
                        json_str = json_str[1:-1].replace('\\"', '"')

                    findings_json = json.loads(json_str)

                    # Ensure it's a list
                    if not isinstance(findings_json, list):
                        raise InvalidFormatError(
                            "Expected the LLM response to be a list of findings."
                        )

                    # Convert to Finding objects
                    findings.extend([Finding(**finding) for finding in findings_json])

                except json.JSONDecodeError as e:
                    logger.error(f"JSON Parsing Error in one of the JSON blocks: {str(e)}")
                    continue  # Skip invalid JSON blocks

            if not findings:
                raise JSONParsingError("Failed to parse any valid findings from LLM response.")

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


def _clean_invalid_json(raw_json: str) -> str:
    """
    Attempts to clean and fix common issues in invalid JSON strings.

    Args:
        raw_json (str): The raw JSON string to clean.

    Returns:
        str: The cleaned JSON string.
    """
    import re

    # Remove any leading/trailing text before/after JSON array
    json_start = raw_json.find("[")
    json_end = raw_json.rfind("]") + 1
    if json_start != -1 and json_end != -1:
        raw_json = raw_json[json_start:json_end]
    else:
        # If proper JSON array brackets are not found, return the original string
        return raw_json

    # Remove comments (e.g., // comment or /* comment */)
    raw_json = re.sub(r"//.*", "", raw_json)
    raw_json = re.sub(r"/\*[\s\S]*?\*/", "", raw_json)

    # Remove extra commas before closing brackets
    raw_json = re.sub(r",\s*(\]|\})", r"\1", raw_json)

    # Replace single quotes with double quotes
    raw_json = raw_json.replace("'", '"')

    # Remove any control characters
    raw_json = "".join(c for c in raw_json if ord(c) >= 32)

    return raw_json
