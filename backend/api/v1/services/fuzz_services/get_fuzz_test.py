from typing import List, Optional

from api.v1.helpers.project_helpers import compile_project
from api.v1.helpers.retry_helper import retry_async_operation
from api.v1.services.fuzz_services.save_fuzz_test import save_fuzz_test
from common import logger
from common.parse_llm_response import extract_code_from_response
from common.profiles import Profiles, load_profile
from common.send_prompt_to_llm import send_prompt_to_llm_async
from config.prompts.fuzzer_prompts import FUZZ_TEST_VALIDATION_PROMPT
from config.settings import LLM_MODEL_BEST


async def get_fuzz_test(
    prompt: str,
    system_prompt: str,
    detected_profile: Profiles,
    project_dir: str,
    contract_folders: List[str],
    project_structure: str,
    invariants: str,
) -> str:
    """
    Sends the fuzz test prompt to the LLM, retrieves the generated fuzz test, validates it, and ensures it compiles.
    The function handles the generation of the fuzz test, checks for compilation errors, and attempts to fix any issues.

    Args:
        prompt (str): The prompt to send to the LLM for generating the fuzz test.
        system_prompt (str): The system prompt for the LLM, providing context for the generation.
        detected_profile (Profiles): The detected profile, if any, used for context in generation.
        project_dir (str): The project directory where the contracts are located.
        contract_folders (List[str]): The list of folders containing the contract files.
        project_structure (str): The structure of the project, detailing the organization of contracts.
        invariants (str): The invariants to be tested against the generated fuzz test.

    Returns:
        str: The generated and validated fuzz test as a string.
    """

    logger.info("Generating fuzz tests from invariants...")

    async def generate_and_validate_fuzz_test():
        # Generate initial fuzz test
        initial_fuzz_test = await generate_initial_fuzz_test(
            prompt, system_prompt, detected_profile
        )

        # Save and compile the fuzz test, capturing any compilation error
        compilation_error = await save_and_compile_fuzz_test(
            initial_fuzz_test, project_dir, contract_folders
        )

        # If compilation failed, try to fix the fuzz test suite
        validated_fuzz_test = await validate_fuzz_test(
            initial_fuzz_test, project_structure, invariants, compilation_error
        )

        # Save and compile the validated fuzz test
        await save_and_compile_fuzz_test(validated_fuzz_test, project_dir, contract_folders)

        return validated_fuzz_test

    fuzz_test: str = await retry_async_operation(generate_and_validate_fuzz_test)

    return fuzz_test


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
        return fuzz_test

    except Exception as e:
        logger.exception(f"Error in generate_initial_fuzz_test: {str(e)}")
        raise


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
        return None  # No compilation error
    except Exception as e:
        logger.exception(f"Error in save_and_compile_fuzz_test: {str(e)}")
        return str(e)
