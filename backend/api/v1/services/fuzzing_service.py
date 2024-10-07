import shutil
import tempfile
from typing import Dict, Optional, Union

from api.v1.schemas.fuzzer_schema import FuzzTestResult, SetupResult
from api.v1.services.fuzz_services.extract_fuzz_test import extract_fuzz_test
from api.v1.services.fuzz_services.generate_fuzz_prompts import generate_fuzz_prompts
from api.v1.services.fuzz_services.generate_report_prompt import generate_report_prompt
from api.v1.services.fuzz_services.run_fuzz_file import run_fuzz_file
from api.v1.services.fuzz_services.save_fuzz_test import save_fuzz_test
from api.v1.utils.slither_helpers import run_slither
from common import logger
from common.send_prompt_to_llm import send_prompt_to_llm_async
from common.setup_environment import setup_environment
from config.settings import LLM_MODEL_FUZZER


async def run_fuzzer(
    github_url: str,
    oauth_token: Optional[str] = None,
    temp_dir: Optional[str] = None,
) -> Dict[str, Union[Optional[str], str]]:
    """
    Executes the fuzzing process on a specified GitHub repository using Slither for context.

    This function sets up the environment, runs Slither analysis to gather context, generates fuzzing prompts incorporating Slither output,
    sends the prompts to a language model, extracts and saves the fuzz test, runs the fuzz test, generates a report based on the results, and converts the report to JSON.

    Args:
        github_url (str): The GitHub repository URL.
        oauth_token (Optional[str]): The OAuth token for private repositories.

    Returns:
        Dict[str, Union[Optional[str], str]]: A dictionary containing the fuzz test, fuzz results, analysis, and any error encountered.
    """
    model = LLM_MODEL_FUZZER
    is_local_temp_dir = False
    if temp_dir is None:
        temp_dir = tempfile.mkdtemp()
        is_local_temp_dir = True

    try:
        # 1. Setup the fuzzing environment
        setup_result: SetupResult = await setup_environment(github_url, oauth_token, temp_dir)
        logger.info(f"Project type: {setup_result.project_type}")

        # Update project_dir to be from setup_result
        project_dir = setup_result.project_dir
        contract_folders = setup_result.contract_folders
        solc_version = setup_result.solc_version
        # project_path = setup_result.project_path

        # 2. Run Slither analysis
        logger.info("Running Slither")
        slither_output = await run_slither(project_dir)

        # 3. Generate fuzz prompts (with slither output)
        logger.info("Generating fuzz prompts")
        fuzz_prompts = await generate_fuzz_prompts(project_dir, contract_folders, slither_output)

        # 4. Send fuzz prompts to LLM
        logger.info("Sending fuzz prompts to LLM")
        fuzz_response = await send_prompt_to_llm_async(model, fuzz_prompts)

        # 5. Extract fuzz test
        logger.info("Extracting fuzz test")
        fuzz_test = extract_fuzz_test(fuzz_response)

        # 6. Save fuzz test
        logger.info("Saving fuzz test")
        try:
            await save_fuzz_test(fuzz_test, project_dir, contract_folders, solc_version)
        except Exception as e:
            logger.error(
                f"Failed to save fuzz test: {str(e)}. Regenerating fuzz prompts and retrying."
            )
            fuzz_prompts = await generate_fuzz_prompts(
                project_dir, contract_folders, slither_output
            )
            fuzz_response = await send_prompt_to_llm_async(model, fuzz_prompts)
            fuzz_test = extract_fuzz_test(fuzz_response)
            await save_fuzz_test(fuzz_test, project_dir, contract_folders, solc_version)

        # 7. Run fuzz test
        logger.info("Running fuzz test")
        fuzz_results = await run_fuzz_file(project_dir)
        logger.info(f"Fuzz results: {fuzz_results}")

        # 8. Generate report prompt
        logger.info("Generating report prompt")
        report_prompt = await generate_report_prompt(fuzz_test, fuzz_results)

        # 9. Send report prompt to LLM
        logger.info("Sending report prompt to LLM")
        report_response = await send_prompt_to_llm_async(model, report_prompt)

        # 10. Convert the report to JSON
        report_json = FuzzTestResult(
            fuzz_test=fuzz_test,
            fuzz_results=fuzz_results,
            analysis=report_response,
        )

        if is_local_temp_dir:
            logger.info("Cleaning up environment")
            shutil.rmtree(temp_dir)

        return {
            "message": "Fuzzing completed successfully.",
            "status": "Success",
            "data": report_json,
            "error": None,
        }
    except Exception as e:
        return {
            "message": "An error occurred during the fuzzing process.",
            "status": "Error",
            "data": None,
            "error": str(e),
        }
