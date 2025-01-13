import json
import re
from typing import Optional, Type, TypeVar, Union

from fastapi import HTTPException
from pydantic import BaseModel, ValidationError

from config.settings import SUPPORTED_MODELS
from core.utils.logger import logger

T = TypeVar("T", bound=BaseModel)


def parse_model_response(
    content: str, response_model: Optional[Type[T]], model_type: Optional[str] = None
) -> Union[T, str]:
    """
    Parse and clean the LLM response content into the specified Pydantic model.

    Args:
        content (str): The raw content returned by the LLM.
        response_model (Optional[Type[T]]): The Pydantic model to parse the content into.
        model_type (Optional[str]): The type of model that generated the response.

    Returns:
        Union[T, str]: An instance of the response_model parsed from the content, or raw content if no model is provided.

    Raises:
        HTTPException: If any error occurs during parsing or validation.
    """
    if response_model is None:
        return content

    try:
        # 1. Special handling for Gemini responses
        if model_type in SUPPORTED_MODELS.get("gemini", []):
            cleaned_content = _clean_gemini_response(content)
            try:
                parsed_json = json.loads(cleaned_content)
                return response_model.model_validate(parsed_json)
            except (json.JSONDecodeError, ValidationError) as e:
                logger.debug(
                    f"Gemini parsing failed: {str(e)} / Errors: {getattr(e, 'errors', lambda: None)()}, "
                    "falling back to standard parsing..."
                )

        # 2. Try direct parsing first (fastest)
        try:
            parsed_json = json.loads(content)
            return response_model.model_validate(parsed_json)
        except (json.JSONDecodeError, ValidationError):
            logger.debug("Direct parsing failed, trying cleanup steps...")

        # 3. Basic cleanup and retry
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

        # 4. Try to extract JSON structure
        json_content = extract_json(cleaned_content)
        if json_content:
            try:
                parsed_json = json.loads(json_content)
                return response_model.model_validate(parsed_json)
            except (json.JSONDecodeError, ValidationError):
                logger.debug("JSON extraction failed, trying advanced cleaning...")

        # 5. Advanced cleaning as last resort
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
            ) from e

    except HTTPException:
        raise
    except Exception as e:
        logger.exception(f"Unexpected error in parse_model_response: {str(e)}")
        raise HTTPException(status_code=500, detail="Failed to parse response") from e


def _clean_gemini_response(content: str) -> str:
    """Special cleaning for Gemini responses that often contain unescaped newlines in strings."""
    # First try to parse as-is
    try:
        json.loads(content)
        return content
    except json.JSONDecodeError:
        pass

    # If that fails, try to extract the JSON structure while preserving content
    try:
        # Find the outermost JSON structure
        json_match = re.search(r"({[\s\S]*})", content)
        if json_match:
            content = json_match.group(1)

            code_blocks = []

            def save_code_block(match):
                code_blocks.append(match.group(0))
                return f"__CODE_BLOCK_{len(code_blocks)-1}__"

            content = re.sub(r"```(?:\w+)?[\s\S]*?```", save_code_block, content)

            # 2. Clean and normalize the JSON structure
            # Remove whitespace between properties
            content = re.sub(r"\s+", " ", content)
            # Remove spaces after colons and commas
            content = re.sub(r":\s+", ":", content)
            content = re.sub(r",\s+", ",", content)
            # Remove spaces inside brackets
            content = re.sub(r"{\s+", "{", content)
            content = re.sub(r"\s+}", "}", content)

            # 3. Handle multiline strings
            def clean_string(match):
                string_content = match.group(1)
                # Join multiple lines and normalize whitespace
                string_content = " ".join(
                    line.strip() for line in string_content.split("\n") if line.strip()
                )
                return f'"{string_content}"'

            content = re.sub(r'"([^"]*?(?:\n[^"]*?)*)"', clean_string, content)

            # 4. Restore code blocks
            for i, block in enumerate(code_blocks):
                content = content.replace(
                    f"__CODE_BLOCK_{i}__", block.replace("\n", "\\n").replace('"', '\\"')
                )

            # 5. Final cleanup of any remaining control characters
            content = re.sub(r"[\x00-\x1F\x7F-\x9F]", "", content)

            return content
    except Exception as e:
        logger.error(f"Error in cleaning JSON: {str(e)}")
        pass

    # If all else fails, return the original content
    return content


def _clean_json_content(content: str) -> str:
    """Comprehensive JSON cleaning for various edge cases."""
    # If there's an odd number of triple backticks, try to close them
    backtick_count = content.count("```")
    if backtick_count % 2 != 0:
        content += "\n```"

    content = content.strip()

    # Replace fancy quotes with regular quotes
    content = content.replace(""", '"').replace(""", '"')
    content = content.replace("'", "'").replace("'", "'")

    # --- STEP 1: Handle code blocks carefully ---
    # We will modify your existing code block capture to also escape quotes
    def code_block_replacer(match: re.Match) -> str:
        """
        - match.group(1) = code language, e.g. 'solidity'
        - match.group(2) = the actual code content
        """
        lang = match.group(1)
        code = match.group(2)

        # 1) Strip trailing whitespace
        code = code.strip()

        # 2) Escape any double quotes that are not already escaped
        #    We use a negative lookbehind `(?<!\\)` to avoid re-escaping already escaped quotes.
        code = re.sub(r'(?<!\\)"', r'\\"', code)

        # 3) Return a safely re-embedded code block
        return f"```{lang}\\n{code}\\n```"

    # Look for triple-backtick code blocks: ```<lang>\n...code...\n```
    content = re.sub(
        r"```(\w+)\n(.*?)```",
        code_block_replacer,
        content,
        flags=re.DOTALL,
    )
    # --- end code blocks step ---

    # --- STEP 2: Remove control characters outside code blocks ---
    def clean_outside_code_blocks(text: str) -> str:
        parts = []
        current_pos = 0
        code_block_regex = r"```(\w+)\\n.*?\\n```"

        for match in re.finditer(code_block_regex, text, re.DOTALL):
            # Clean text before the code block
            # flake8: noqa: E203
            before_block = text[current_pos : match.start()]
            cleaned_before = re.sub(r"[\x00-\x1F\x7F-\x9F]", "", before_block)
            parts.append(cleaned_before)

            # Keep the code block as is
            parts.append(match.group(0))
            current_pos = match.end()

        # Clean remaining text after the last code block
        if current_pos < len(text):
            remaining = text[current_pos:]
            cleaned_remaining = re.sub(r"[\x00-\x1F\x7F-\x9F]", "", remaining)
            parts.append(cleaned_remaining)

        return "".join(parts)

    content = clean_outside_code_blocks(content)

    # --- STEP 3: Fix common JSON issues ---
    # Remove unnecessary escapes like \[char] (but keep \n, \")
    content = re.sub(r"\\([^\"n\\])", r"\1", content)

    # Remove trailing commas: ,} or ,]
    content = re.sub(r",(\s*[}\]])", r"\1", content)

    # Collapse multiple blank lines, e.g. "\\n\\n" -> "\\n"
    content = re.sub(r"\\n\s*\\n", "\\n", content)

    # --- STEP 4: Attempt to extract the main JSON structure
    json_match = re.search(r"({[\s\S]*})", content)
    if json_match:
        content = json_match.group(1)

    return content.strip()


def extract_json(text: str) -> Optional[str]:
    """Extract the first valid JSON structure from text."""
    # First try to find JSON between code block markers
    code_block_match = re.search(r"```(?:json)?\s*({[\s\S]*?})\s*```", text)
    if code_block_match:
        try:
            potential_json = code_block_match.group(1).strip()
            json.loads(potential_json)  # Validate it's proper JSON
            return potential_json
        except json.JSONDecodeError:
            pass

    # Then try to find any JSON-like structure
    json_pattern = r"({(?:[^{}]|{[^{}]*})*})"
    matches = re.finditer(json_pattern, text)

    for match in matches:
        potential_json = match.group(1)
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

    raise ValueError("No Solidity fuzz test found in the LLM response.")
