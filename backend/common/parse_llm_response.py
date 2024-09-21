import json
import re
from typing import Optional, Type, TypeVar, Union

from common import logger
from pydantic import BaseModel, ValidationError

T = TypeVar("T", bound=BaseModel)


def parse_model_response(
    content: str, response_model: Optional[Type[T]]
) -> Optional[Union[T, str]]:
    """
    Parse and clean the LLM response content into the specified Pydantic model.

    Args:
        content (str): The raw content returned by the LLM.
        response_model (Optional[Type[T]]): The Pydantic model to parse the content into.

    Returns:
        Optional[T]: An instance of the response_model parsed from the content, or None if parsing fails.
    """
    if response_model is None:
        return content

    try:
        # Extract JSON content from the response
        json_content = extract_json(content)
        if not json_content:
            logger.error("No JSON content found in the LLM response.")
            return None

        # Clean the JSON content
        json_content_clean = remove_control_characters(json_content)

        # Attempt to parse the JSON content
        parsed_json = try_parse_json(json_content_clean)
        if parsed_json is None:
            logger.error("Failed to parse JSON content.")
            return None

        # Try to parse using response_model
        try:
            structured_response = response_model.model_validate(parsed_json)
            return structured_response
        except ValidationError as e:
            logger.debug(f"ValidationError: {e}")

            # Handle the case where the parsed JSON is a list but the model expects a dict
            if isinstance(parsed_json, list):
                # Check if the model has a single field that accepts a list
                model_fields = response_model.model_fields
                list_field_name = None
                for field_name, field_info in model_fields.items():
                    field_type = field_info.outer_type_
                    if getattr(field_type, "__origin__", None) is list:
                        list_field_name = field_name
                        break

                if list_field_name:
                    wrapped_json = {list_field_name: parsed_json}
                    try:
                        structured_response = response_model.model_validate(wrapped_json)
                        return structured_response
                    except ValidationError as e2:
                        logger.error(f"Validation error after wrapping: {e2}")
                        return None
            logger.error(f"Validation error parsing JSON into {response_model}: {e}")
            return None

    except Exception as e:
        logger.error(f"Error parsing response into {response_model}: {e}")
        return None


def extract_json(text: str) -> Optional[str]:
    """
    Extracts JSON content from a text string, considering nested structures.
    """
    json_start = None
    json_end = None
    brace_stack = []

    for idx, char in enumerate(text):
        if char == "{" or char == "[":
            if not brace_stack:
                json_start = idx
            brace_stack.append(char)
        elif char == "}" or char == "]":
            if brace_stack:
                brace_stack.pop()
                if not brace_stack:
                    json_end = idx + 1
                    break

    if json_start is not None and json_end is not None:
        return text[json_start:json_end]
    else:
        return None


def try_parse_json(json_str: str) -> Optional[Union[dict, list]]:
    # Attempt to parse JSON content, trying several strategies
    try:
        return json.loads(json_str)
    except json.JSONDecodeError:
        # Attempt to fix common JSON issues
        fixed_json_str = _clean_invalid_json(json_str)
        try:
            return json.loads(fixed_json_str)
        except json.JSONDecodeError as e:
            logger.error(f"JSON Parsing Error after cleaning: {e}")
            return None


def _clean_invalid_json(raw_json: str) -> str:
    """
    Attempts to clean and fix common issues in invalid JSON strings.
    """
    # Remove comments
    raw_json = re.sub(r"//.*", "", raw_json)
    raw_json = re.sub(r"/\*[\s\S]*?\*/", "", raw_json)

    # Remove extra commas before closing brackets
    raw_json = re.sub(r",\s*(\]|\})", r"\1", raw_json)

    # Replace single quotes with double quotes cautiously
    raw_json = re.sub(r"(?<=[:\s])'([^']*)'", r'"\1"', raw_json)

    # Remove control characters
    raw_json = "".join(c for c in raw_json if ord(c) >= 32)

    # Trim whitespace
    raw_json = raw_json.strip()

    return raw_json


def remove_control_characters(json_content: str) -> str:
    # Remove control characters that are invalid in JSON strings
    control_chars = "".join(map(chr, range(0, 32))) + "".join(map(chr, range(127, 160)))
    control_char_regex = f"[{re.escape(control_chars)}]"
    json_content = re.sub(control_char_regex, "", json_content)

    # Replace curly quotes with straight quotes
    json_content = json_content.replace(
        """, ""').replace(""",
        """)
    json_content = json_content.replace(""', ""').replace(""', """,
    )

    # Remove zero-width or non-printing Unicode characters
    json_content = re.sub(r"[\u200B-\u200D\uFEFF]", "", json_content)

    # Trim leading/trailing whitespace
    json_content = json_content.strip()

    return json_content
