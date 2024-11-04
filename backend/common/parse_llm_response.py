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
        # 1. Try direct parsing first (fastest)
        try:
            parsed_json = json.loads(content)
            return response_model.model_validate(parsed_json)
        except (json.JSONDecodeError, ValidationError):
            logger.debug("Direct parsing failed, trying cleanup steps...")

        # 2. Basic cleanup and retry
        cleaned_content = content.strip()
        if cleaned_content.startswith("```") or cleaned_content.startswith("```json"):
            # Remove markdown code blocks
            lines = cleaned_content.split("\n")
            cleaned_content = "\n".join(
                line for line in lines if not line.strip().startswith("```")
            ).strip()

            try:
                parsed_json = json.loads(cleaned_content)
                return response_model.model_validate(parsed_json)
            except (json.JSONDecodeError, ValidationError):
                logger.debug("Basic markdown cleanup failed, trying JSON extraction...")

        # 3. Try to extract JSON structure
        json_content = extract_json(cleaned_content)
        if json_content:
            try:
                parsed_json = json.loads(json_content)
                return response_model.model_validate(parsed_json)
            except (json.JSONDecodeError, ValidationError):
                logger.debug("JSON extraction failed, trying advanced cleaning...")

        # 4. Advanced cleaning as last resort
        cleaned_json = _clean_json_content(cleaned_content)
        try:
            parsed_json = json.loads(cleaned_json)
            return response_model.model_validate(parsed_json)
        except (json.JSONDecodeError, ValidationError) as e:
            logger.error(f"All parsing attempts failed. Final error: {str(e)}")
            logger.error("Original content:", content[:200])
            logger.error("After cleaning:", cleaned_json[:200])
            raise HTTPException(
                status_code=400, detail=f"Failed to parse content into {response_model.__name__}"
            )

    except HTTPException:
        raise
    except Exception as e:
        logger.exception(f"Unexpected error in parse_model_response: {str(e)}")
        raise HTTPException(status_code=500, detail="Failed to parse response")


def _clean_json_content(content: str) -> str:
    """Comprehensive JSON cleaning for various edge cases."""
    # Remove control characters (from old version)
    control_chars = "".join(map(chr, range(0, 32))) + "".join(map(chr, range(127, 160)))
    control_char_regex = f"[{re.escape(control_chars)}]"
    content = re.sub(control_char_regex, "", content)

    # Replace curly quotes (from old version)
    content = content.replace(""", '"').replace(""", '"')
    content = content.replace("'", "'").replace("'", "'")

    # Remove zero-width characters (from old version)
    content = re.sub(r"[\u200B-\u200D\uFEFF]", "", content)

    # New version cleaning
    content = re.sub(r"`([^`]+)`", r"\1", content)  # Handle inline code
    content = re.sub(r"```\w*\n?|\n?```", "", content)  # Remove markdown
    content = content.replace('\\"', '"')  # Fix escaped chars
    content = content.replace("\\n", "\n")
    content = re.sub(r'\\+(["{}\[\]])', r"\1", content)  # Handle nested JSON
    content = re.sub(r",(\s*[}\]])", r"\1", content)  # Fix trailing commas

    # Handle multiline code snippets
    def clean_code_block(match):
        code = match.group(1)
        return code.replace("\n", "\\n").replace('"', '\\"')

    content = re.sub(
        r'("code":\s*")(.*?)(")',
        lambda m: m.group(1) + clean_code_block(m) + m.group(3),
        content,
        flags=re.DOTALL,
    )

    # Extract main JSON structure
    json_match = re.search(r"({[\s\S]*}|\[[\s\S]*\])", content)
    if json_match:
        content = json_match.group(0)

    return content.strip()


def extract_json(text: str) -> Optional[str]:
    """Extract the first valid JSON structure from text."""
    # Find all potential JSON objects/arrays
    starts = []
    stack = []
    json_ranges = []

    for i, char in enumerate(text):
        if char in "{[":
            if not stack:
                starts.append(i)
            stack.append(char)
        elif char in "}]":
            if stack:
                opening = stack.pop()
                if not stack:  # Complete JSON structure found
                    if (opening == "{" and char == "}") or (opening == "[" and char == "]"):
                        json_ranges.append((starts.pop(), i + 1))

    # Try each potential JSON structure
    for start, end in json_ranges:
        potential_json = text[start:end]
        try:
            json.loads(potential_json)  # Validate it's proper JSON
            return potential_json
        except json.JSONDecodeError:
            continue

    return None


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
