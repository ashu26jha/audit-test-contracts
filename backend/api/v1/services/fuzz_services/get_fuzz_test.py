from typing import List, Optional, Tuple

from api.v1.helpers.project_helpers import compile_project
from api.v1.services.fuzz_services.save_fuzz_test import save_fuzz_test
from common import logger
from common.parse_llm_response import extract_code_from_response
from common.profiles import Profiles, load_profile
from common.send_prompt_to_llm import send_prompt_to_llm_async
from config.prompts.fuzzer_prompts import FUZZ_TEST_VALIDATION_PROMPT
from config.settings import LLM_MODEL_BEST, MAX_RETRIES


class CompilationError(Exception):
    """Custom exception to indicate compilation failure."""

    pass


async def get_fuzz_test(
    prompt: str,
    system_prompt: str,
    detected_profile: Profiles,
    project_dir: str,
    contract_folders: List[str],
    project_structure: str,
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
        contract_folders (List[str]): The list of folders containing the contract files.
        project_structure (str): The structure of the project, detailing the organization of contracts.
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
                contract_folders,
                project_structure,
                invariants,
            )
            logger.info("Fuzz test generated and compiled successfully.")
            return fuzz_test, None  # Success
        except CompilationError as ce:
            logger.warning(f"Compilation failed on attempt {attempt}: {str(ce)}")
            if attempt == MAX_RETRIES:
                logger.error("Max retries reached. Failed to generate a valid fuzz test.")
                return "", str(ce)
            else:
                logger.info("Attempting to fix and retry the fuzz test.")
        except Exception as e:
            logger.exception(f"Unexpected error on attempt {attempt}: {str(e)}")
            if attempt == MAX_RETRIES:
                logger.error("Max retries reached. Failed to generate a valid fuzz test.")
                return "", str(e)
            else:
                logger.info("Attempting to retry after unexpected error.")

    # If all retries fail, return an error
    return "", "Failed to generate a valid fuzz test after multiple attempts."


async def generate_initial_fuzz_test(
    prompt: str, system_prompt: str, detected_profile: Profiles
) -> str:
    model = LLM_MODEL_BEST
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
    contract_folders: List[str],
    project_structure: str,
    invariants: str,
) -> str:
    """
    Validates and compiles the fuzz test. If compilation fails, attempts to fix it.

    Args:
        fuzz_test (str): The current fuzz test code.
        project_dir (str): The project directory.
        contract_folders (List[str]): List of contract folders.
        project_structure (str): Structure of the project.
        invariants (str): Invariants to test against.

    Returns:
        str: The validated and potentially fixed fuzz test.

    Raises:
        CompilationError: If compilation fails after attempting to fix.
    """
    # Try to compile the fuzz test
    compilation_error = await save_and_compile_fuzz_test(fuzz_test, project_dir, contract_folders)

    if compilation_error:
        logger.warning(f"Compilation error detected: {compilation_error}")
        logger.info("Attempting to fix and validate the fuzz test.")
        try:
            fixed_fuzz_test = await validate_fuzz_test(
                fuzz_test, project_structure, invariants, compilation_error
            )
            # After fixing, attempt to compile again
            new_compilation_error = await save_and_compile_fuzz_test(
                fixed_fuzz_test, project_dir, contract_folders
            )
            if new_compilation_error:
                logger.error(f"Compilation failed after fix: {new_compilation_error}")
                raise CompilationError(new_compilation_error)
            logger.info("Fuzz test fixed and compiled successfully.")
            return fixed_fuzz_test
        except Exception as e:
            logger.exception(f"Error in fixing fuzz test: {str(e)}")
            raise CompilationError(str(e))
    else:
        # No compilation error
        return fuzz_test


async def validate_fuzz_test(
    fuzz_test: str,
    project_structure: str,
    invariants: str,
    compilation_error: Optional[str] = None,
) -> str:
    model = LLM_MODEL_BEST
    validation_prompt = FUZZ_TEST_VALIDATION_PROMPT.format(
        fuzz_test=fuzz_test,
        project_structure=project_structure,
        invariants=invariants,
        compilation_error=(compilation_error if compilation_error else "No compilation errors."),
    )

    try:
        llm_response = await send_prompt_to_llm_async(model, validation_prompt)
        validated_fuzz_test = extract_code_from_response(llm_response, language="solidity")
        logger.info("Fuzz test validation and fixing successful.")
        return validated_fuzz_test

    except Exception as e:
        logger.exception(f"Error in validate_fuzz_test: {str(e)}")
        raise


async def save_and_compile_fuzz_test(
    fuzz_test: str, project_dir: str, contract_folders: List[str]
) -> Optional[str]:
    try:
        await save_fuzz_test(fuzz_test, project_dir, contract_folders)
        await compile_project(project_dir)
        logger.info("Fuzz test compiled successfully.")
        return None  # No compilation error
    except Exception as e:
        logger.exception(f"Error in save_and_compile_fuzz_test: {str(e)}")
        return str(e)
