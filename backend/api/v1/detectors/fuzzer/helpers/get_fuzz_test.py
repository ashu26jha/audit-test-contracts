import re  # Import regex module for parsing errors
from typing import List, Optional, Tuple

from api.v1.common.project_helpers import compile_project
from api.v1.detectors.fuzzer.helpers.save_fuzz_test import save_fuzz_test
from config.prompts.fuzzer_prompts import FUZZ_TEST_VALIDATION_PROMPT
from config.settings import LLM_SCAN_1, MAX_RETRIES
from core.llm.parse_llm_response import extract_code_from_response
from core.llm.send_prompt_to_llm import send_prompt_to_llm_async
from core.utils.logger import logger
from core.utils.profiles import Profiles, load_profile


class CompilationError(Exception):
    """Raised when compilation of a contract fails."""


async def get_fuzz_test(
    prompt: str,
    system_prompt: str,
    detected_profile: Profiles,
    project_dir: str,
    project_structure: str,
    remappings: List[str],
    invariants: str,
) -> Tuple[str, Optional[str]]:
    """
    Generates a fuzz test, attempts to compile it, and if compilation fails,
    tries to fix the test up to three times.

    Args:
        prompt (str): The prompt to send to the LLM for generating the fuzz test.
        system_prompt (str): The system prompt for the LLM, providing context for the generation.
        detected_profile (Profiles): The detected profile, if any, used for context in generation.
        project_dir (str): The project directory where the contracts are located.
        project_structure (str): The structure of the project, detailing the organization of contracts.
        remappings (List[str]): The remappings to be used for the fuzz test.
        invariants (str): The invariants to be tested against the generated fuzz test.

    Returns:
        Tuple[str, Optional[str]]: A tuple containing the generated and validated fuzz test as a string,
            and any final compilation error as a string, or None if successful.
    """

    logger.info("Generating fuzz tests from invariants...")

    # Generate initial fuzz test (only once)
    fuzz_test = await generate_initial_fuzz_test(prompt, system_prompt, detected_profile)

    for attempt in range(1, MAX_RETRIES + 1):
        logger.info(f"Attempt {attempt} to validate and compile the fuzz test.")
        try:
            # Attempt to validate and compile the current fuzz_test
            fuzz_test = await validate_and_compile_fuzz_test(
                fuzz_test,
                project_dir,
                project_structure,
                remappings,
                invariants,
            )
            logger.info("Fuzz test generated and compiled successfully.")
            return fuzz_test, None  # Success
        except CompilationError as ce:
            # logger.warning(f"Compilation failed on attempt {attempt}: {str(ce)}")
            logger.warning(f"Compilation failed on attempt {attempt}.")
            if attempt == MAX_RETRIES:
                logger.error("Max retries reached. Failed to generate a valid fuzz test.")
                return "", str(ce)

            logger.info("Attempting to fix and retry the fuzz test.")
        except Exception as e:
            logger.exception(f"Unexpected error on attempt {attempt}: {str(e)}")
            if attempt == MAX_RETRIES:
                logger.error("Max retries reached. Failed to generate a valid fuzz test.")
                return "", str(e)

            logger.info("Attempting to retry after unexpected error.")

    # If all retries fail, return an error
    return "", "Failed to generate a valid fuzz test after multiple attempts."


async def generate_initial_fuzz_test(
    prompt: str, system_prompt: str, detected_profile: Profiles
) -> str:
    model = LLM_SCAN_1
    message_history = load_profile(detected_profile)

    try:
        llm_response = await send_prompt_to_llm_async(model, prompt, system_prompt, message_history)

        if not llm_response or not isinstance(llm_response, str):
            raise ValueError("LLM response was empty or invalid")

        # Extract the Solidity code from the response
        fuzz_test = extract_code_from_response(llm_response, language="solidity")
        logger.info("Initial fuzz test generated successfully.")
        return fuzz_test

    except Exception as e:
        logger.exception(f"Error in generate_initial_fuzz_test: {str(e)}")
        raise


async def validate_and_compile_fuzz_test(
    fuzz_test: str,
    project_dir: str,
    project_structure: str,
    remappings: List[str],
    invariants: str,
) -> str:
    """
    Validates and compiles the fuzz test. If compilation fails, attempts to fix it.

    Args:
        fuzz_test (str): The current fuzz test code.
        project_dir (str): The project directory.
        project_structure (str): Structure of the project.
        remappings (List[str]): Remappings to be used for the fuzz test.
        invariants (str): Invariants to test against.

    Returns:
        str: The validated and potentially fixed fuzz test.

    Raises:
        CompilationError: If compilation fails after attempting to fix.
    """

    # Try to compile the fuzz test
    compilation_error = await save_and_compile_fuzz_test(fuzz_test, project_dir)

    if compilation_error:
        # logger.warning(f"Compilation error detected: {compilation_error}")
        logger.warning("Compilation error detected.")
        logger.info("Attempting to fix and validate the fuzz test.")
        try:
            fixed_fuzz_test = await validate_fuzz_test(
                fuzz_test, project_structure, invariants, remappings, compilation_error
            )
            # After fixing, attempt to compile again
            new_compilation_error = await save_and_compile_fuzz_test(fixed_fuzz_test, project_dir)
            if new_compilation_error:
                logger.error(f"Compilation failed after fix: {new_compilation_error}")
                raise CompilationError(new_compilation_error)
            logger.info("Fuzz test fixed and compiled successfully.")
            return fixed_fuzz_test
        except Exception as e:
            logger.exception(f"Error in fixing fuzz test: {str(e)}")
            raise CompilationError(str(e)) from e
    else:
        # No compilation error
        return fuzz_test


async def validate_fuzz_test(
    fuzz_test: str,
    project_structure: str,
    invariants: str,
    remappings: List[str],
    compilation_error: Optional[str] = None,
) -> str:
    model = LLM_SCAN_1
    validation_prompt = FUZZ_TEST_VALIDATION_PROMPT.format(
        compilation_error=(compilation_error if compilation_error else "No compilation errors."),
        fuzz_test=fuzz_test,
        project_structure=project_structure,
        invariants=invariants,
        remappings=remappings,
    )

    try:
        llm_response = await send_prompt_to_llm_async(model, validation_prompt)
        validated_fuzz_test = extract_code_from_response(llm_response, language="solidity")
        logger.info("Fuzz test validation and fixing successful.")
        return validated_fuzz_test

    except Exception as e:
        logger.exception(f"Error in validate_fuzz_test: {str(e)}")
        raise


async def save_and_compile_fuzz_test(fuzz_test: str, project_dir: str) -> Optional[str]:
    try:
        await save_fuzz_test(fuzz_test, project_dir)
        await compile_project(project_dir)
        logger.info("Fuzz test compiled successfully.")
        return None  # No compilation error
    except Exception as e:
        # logger.exception(f"Error in save_and_compile_fuzz_test: {str(e)}")
        logger.exception("Error in save_and_compile_fuzz_test")
        # Extract relevant error information
        error_message = str(e)
        parsed_error = parse_compilation_error(error_message)
        return parsed_error


def parse_compilation_error(error_message: str) -> str:
    """
    Parses the compilation error message to extract relevant details.
    """
    # Example regex to extract error code, file, line number, and message
    pattern = r"Error \((\d+)\): (?>.*?)\n\s+--> (?>.*?):(?>[\d]+):(?>[\d]+):\n\s+\|\n\s+\d+\s+\|\s+(?>.*?)\n"
    matches = re.findall(pattern, error_message, re.MULTILINE)
    parsed_errors = []
    for match in matches:
        _, error_description, file_path, line, column, code_line = match
        parsed_errors.append(
            f"In file {file_path}, line {line}, column {column}: {error_description}. Code: {code_line.strip()}"
        )

    if parsed_errors:
        return "\n".join(parsed_errors)

    # Return the original message if parsing fails
    return error_message
