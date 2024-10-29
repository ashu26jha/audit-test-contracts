import json
import re
from typing import Optional, Type, TypeVar, Union

from fastapi import HTTPException
from pydantic import BaseModel, ValidationError

from common import logger

T = TypeVar("T", bound=BaseModel)


def parse_model_response(content: str, response_model: Optional[Type[T]]) -> Union[T, str]:
    """
    Parse and clean the LLM response content into the specified Pydantic model.

    Args:
        content (str): The raw content returned by the LLM.
        response_model (Optional[Type[T]]): The Pydantic model to parse the content into.

    Returns:
        Union[T, str]: An instance of the response_model parsed from the content, or raw content if no model is provided.

    Raises:
        HTTPException: If any error occurs during parsing or validation.
    """
    if response_model is None:
        return content

    try:
        # Extract JSON content from the response
        json_content = extract_json(content)
        if not json_content:
            raise HTTPException(
                status_code=400, detail="No JSON content found in the LLM response."
            )

        # Clean the JSON content
        json_content_clean = remove_control_characters(json_content)

        # Attempt to parse the JSON content
        parsed_json = try_parse_json(json_content_clean)
        if parsed_json is None:
            raise HTTPException(status_code=400, detail="Failed to parse JSON content.")

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
                        raise HTTPException(status_code=500, detail="Internal server error")

            raise HTTPException(
                status_code=500,
                detail=f"Validation error parsing JSON into {response_model}",
            )

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error parsing response into {response_model}: {e}")
        raise HTTPException(status_code=500, detail="Internal server error")


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

    # Fix escaped quotes within JSON strings - look for (`""`) pattern
    raw_json = re.sub(r'\(`""\`\)', '("")', raw_json)
    raw_json = re.sub(r'\(`"([^"]*)"\`\)', r'("\1")', raw_json)

    # Handle markdown code blocks within JSON strings
    def replace_code_block(match):
        # Properly escape the code block content
        code = match.group(1)
        # Normalize newlines
        code = code.replace("\r\n", "\n").replace("\r", "\n")
        # Escape backslashes and quotes
        code = code.replace("\\", "\\\\").replace('"', '\\"')
        # Replace newlines with \n
        code = code.replace("\n", "\\n")
        return f"\\n```solidity\\n{code}\\n```\\n"

    # First normalize all newlines in the entire JSON
    raw_json = raw_json.replace("\r\n", "\n").replace("\r", "\n")

    # Replace markdown code blocks before JSON parsing
    raw_json = re.sub(r"```solidity(.*?)```", replace_code_block, raw_json, flags=re.DOTALL)

    # Properly escape remaining newlines in string values
    def escape_string_content(match):
        content = match.group(1)
        if "```" not in content:  # Don't process content that might contain code blocks
            content = content.replace("\n", "\\n")
        return f'": "{content}'

    raw_json = re.sub(r'": "(.*?)"(?=,|\})', escape_string_content, raw_json, flags=re.DOTALL)

    # Fix unclosed recommendation strings containing code blocks
    raw_json = re.sub(
        r'"Recommendation": "(.*?)(?=},|\])',
        lambda m: f'"Recommendation": "{m.group(1)}"',
        raw_json,
        flags=re.DOTALL,
    )

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
    json_content = json_content.replace(""", '"').replace(""", '"')
    json_content = json_content.replace("'", "'").replace("'", "'")

    # Remove zero-width or non-printing Unicode characters
    json_content = re.sub(r"[\u200B-\u200D\uFEFF]", "", json_content)

    # Trim leading/trailing whitespace
    json_content = json_content.strip()

    return json_content


def extract_code_from_response(content: str, language: str = "solidity") -> str:
    """
    Extracts the Solidity fuzz test from the LLM response.

    Args:
        content (str): The raw content returned by the LLM.
        language (str): The programming language to extract (default is "solidity").

    Returns:
        str: The extracted Solidity fuzz test code.
    """

    # Use regex to find the Solidity code block
    code_match = re.search(rf"```{language}(.*?)```", content, re.DOTALL)

    if code_match:
        # Extract the Solidity code and remove any leading/trailing whitespace
        fuzz_test = code_match.group(1).strip()

        # Remove any remaining "```" if present
        fuzz_test = fuzz_test.replace("```", "")

        return fuzz_test
    else:
        raise ValueError("No Solidity fuzz test found in the LLM response.")
