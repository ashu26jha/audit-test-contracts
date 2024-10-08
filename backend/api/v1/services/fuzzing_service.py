import shutil
import tempfile
import json
from typing import List, Optional

from api.v1.helpers.setup_environment_helpers import setup_environment
from api.v1.helpers.slither_helpers import run_slither
from api.v1.schemas.static_analyzer_schema import SlitherOutput
from api.v1.schemas.fuzzer_schema import (
    Finding,
    FuzzerResponse,
    FuzzTestResult,
    SetupResult,
)
from api.v1.services.fuzz_services.extract_fuzz_test import extract_fuzz_test
from api.v1.services.fuzz_services.generate_fuzz_prompts import generate_fuzz_prompts
from api.v1.services.fuzz_services.generate_report_prompt import generate_report_prompt
from api.v1.services.fuzz_services.run_fuzz_file import run_fuzz_file
from api.v1.services.fuzz_services.save_fuzz_test import save_fuzz_test
from common import logger
from common.send_prompt_to_llm import send_prompt_to_llm_async
from config.settings import LLM_MODEL_BEST


async def run_fuzzer(
    github_url: str,
    oauth_token: Optional[str] = None,
    selected_contracts: List[str] = None,
    setup_result: Optional[SetupResult] = None,
    slither_output: Optional[SlitherOutput] = None,
) -> FuzzerResponse:
    """
    Executes the fuzzing process on a specified GitHub repository using Slither for context.

    This function sets up the environment, runs Slither analysis to gather context, generates fuzzing prompts incorporating Slither output,
    sends the prompts to a language model, extracts and saves the fuzz test, runs the fuzz test, generates a report based on the results, and converts the report to JSON.

    Args:
        github_url (str): The GitHub repository URL.
        oauth_token (Optional[str]): The OAuth token for private repositories.

    Returns:
        FuzzerResponse: A response model containing the fuzz test, fuzz results, analysis, and any error encountered.
    """
    model = LLM_MODEL_BEST
    is_local_temp_dir = False
    temp_dir = setup_result.project_dir if setup_result else tempfile.mkdtemp()

    try:
        # 1. Setup the fuzzing environment
        if setup_result is None:
            is_local_temp_dir = True
            try: 
                setup_result: SetupResult = await setup_environment(github_url, oauth_token, temp_dir)
            except Exception as e:
                logger.error(f"Failed to set up environment: {str(e)}")

        # Update project_dir to be from setup_result
        contract_folders = setup_result.contract_folders
        solc_version = setup_result.solc_version
        temp_dir = setup_result.project_dir

        # 3. Generate fuzz prompts (with slither output)
        logger.info("Generating fuzz prompts")
        fuzz_prompts = await generate_fuzz_prompts(temp_dir, contract_folders, slither_output)

        # 4. Send fuzz prompts to LLM
        logger.info("Sending fuzz prompts to LLM")
        fuzz_response = await send_prompt_to_llm_async(model, fuzz_prompts)

        # 5. Extract fuzz test
        logger.info("Extracting fuzz test")
        fuzz_test = extract_fuzz_test(fuzz_response)

        # 6. Save fuzz test
        logger.info("Saving fuzz test")
        try:
            await save_fuzz_test(fuzz_test, temp_dir, contract_folders, solc_version)
        except Exception as e:
            logger.error(
                f"Failed to save fuzz test: {str(e)}. Regenerating fuzz prompts and retrying."
            )
            fuzz_prompts = await generate_fuzz_prompts(temp_dir, contract_folders, slither_output)
            fuzz_response = await send_prompt_to_llm_async(model, fuzz_prompts)
            fuzz_test = extract_fuzz_test(fuzz_response)
            await save_fuzz_test(fuzz_test, temp_dir, contract_folders, solc_version)

        # 7. Run fuzz test
        logger.info("Running fuzz test")
        fuzz_results = await run_fuzz_file(temp_dir)
        
        # 8. Generate report prompt
        logger.info("Generating report prompt")
        report_prompt = await generate_report_prompt(fuzz_test, fuzz_results)

        # 9. Send report prompt to LLM
        logger.info("Sending report prompt to LLM")
        report_response = await send_prompt_to_llm_async(model, report_prompt)
        
        # Strip the ```json from the report_response and convert it to JSON data
        report_response = report_response.strip("```json").strip("```")
        report_response_json = json.loads(report_response)
        print(report_response_json)

        # 10. Convert the report to JSON
        findings_list = [
            Finding(
                Issue=finding["Issue"],
                Severity=finding["Severity"],
                Contracts=finding["Contracts"],
                Description=finding["Description"],
                Recommendation=finding.get("Recommendation"),
            )
            for finding in report_response_json.get("findings", [])
        ]

        report_json = FuzzTestResult(
            fuzz_test=fuzz_test,
            fuzz_results=fuzz_results,
            analysis=json.dumps(report_response_json),
            findings=findings_list,
        )

        if is_local_temp_dir:
            logger.info("Cleaning up environment")
            shutil.rmtree(temp_dir)

        return FuzzerResponse(
            message="Fuzzing completed successfully.",
            status="Success",
            data=report_json,
            error=None,
        )
    except Exception as e:
        return FuzzerResponse(
            message="An error occurred during the fuzzing process.",
            status="Error",
            data=None,
            error=str(e),
        )
