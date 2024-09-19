import asyncio
import os
import shutil
import uuid
import re
from typing import Dict, Union, Optional
from config.settings import SUPPORTED_MODELS, LLM_MODEL_FUZZER
from common.send_prompt_to_LLM import send_prompt_to_llm_async
from common.profiles import Profiles
from api.v1.services.fuzz_services.contract_validator import validate_contract
from api.v1.services.fuzz_services.setup_environment import setup_environment
from api.v1.services.fuzz_services.generate_fuzz_prompts import generate_fuzz_prompts
from api.v1.services.fuzz_services.extract_fuzz_test import extract_fuzz_test
from api.v1.services.fuzz_services.save_fuzz_test import save_fuzz_test
from api.v1.services.fuzz_services.run_fuzz_file import run_fuzz_file
from api.v1.services.fuzz_services.generate_report_prompt import generate_report_prompt
from api.v1.services.fuzz_services.cleanup_environment import cleanup_environment


async def run_fuzzer(contracts: str, contract_name: str, profile: Optional[str] = "DEFAULT", model: Optional[str] = None) -> Dict[str, Union[Optional[str], str]]:
    """
    Runs the fuzzer on the provided Solidity contract.

    This function performs the following steps:
    1. Validates the contract to ensure it is Solidity code.
    2. Sets up the environment for fuzz testing.
    3. Generates fuzz prompts based on the contract.
    4. Sends the fuzz prompts to a language model (LLM) for processing.
    5. Extracts the fuzz test from the LLM response.
    6. Saves the fuzz test to the project directory.
    7. Runs the fuzz test using Foundry.
    8. Generates a report prompt based on the fuzz test results.
    9. Sends the report prompt to the LLM for analysis.
    10. Converts the final report to JSON format.

    Args:
        contracts (str): The Solidity contract content.
        contract_name (str): The name of the contract file.
        profile (Optional[str]): The profile to use for the fuzzing process. Defaults to "DEFAULT".
        model (Optional[str]): The language model to use. If not specified, the default model is used.

    Returns:
        Dict[str, Union[Optional[str], str]]: A dictionary containing the contract name, fuzz test, fuzz results, analysis, and error (if any).
    """
    # Use the default model if none is specified or if the specified model is not supported
    if model not in SUPPORTED_MODELS:
        model = LLM_MODEL_FUZZER
    
    try:
        # 1. Validate the contract to be solidity code    
        is_valid_contract = validate_contract(contracts)

        # If the contract is not valid, return an error message
        if not is_valid_contract:
            return {
                "contract_name": contract_name,
                "error": "The provided code could not be analyzed since it is not a valid Solidity contract.",
                "fuzz_test": None,
                "fuzz_results": None,
                "analysis": None
            }
        
        # 2. Setup environment
        project_dir, _ = await setup_environment(contracts, contract_name)

        # 3. Generate fuzz prompts
        fuzz_prompts = await generate_fuzz_prompts(project_dir)

        # 4. Send fuzz prompts to LLM
        fuzz_response = await send_prompt_to_llm_async(model, fuzz_prompts)

        # 5. Extract fuzz test
        fuzz_test = extract_fuzz_test(fuzz_response)

        # 6. Save fuzz test
        await save_fuzz_test(fuzz_test, project_dir)

        # 7. Run fuzz test
        fuzz_results = await run_fuzz_file(project_dir)

        # 8. Cleanup environment
        await cleanup_environment(project_dir)

        # 9. Generate report prompt
        report_prompt = await generate_report_prompt(fuzz_test, fuzz_results)

        # 10. Send report prompt to LLM
        report_response = await send_prompt_to_llm_async(model, report_prompt)

        # 11. Convert the report to JSON
        report_json = {
            "contract_name": contract_name,
            "fuzz_test": fuzz_test,
            "fuzz_results": fuzz_results,
            "analysis": report_response,
            "error": None
        }

        return report_json
    except Exception as e:
        # If an error occurs during the process, return an error message
        return {
            "contract_name": contract_name,
            "error": str(e),
            "fuzz_test": None,
            "fuzz_results": None,
            "analysis": None
        }