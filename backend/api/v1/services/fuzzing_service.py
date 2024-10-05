from typing import Dict, Optional, Union

from api.v1.services.fuzz_services.cleanup_environment import cleanup_environment
from api.v1.services.fuzz_services.extract_fuzz_test import extract_fuzz_test
from api.v1.services.fuzz_services.generate_fuzz_prompts import generate_fuzz_prompts
from api.v1.services.fuzz_services.generate_report_prompt import generate_report_prompt
from api.v1.services.fuzz_services.run_fuzz_file import run_fuzz_file
from api.v1.services.fuzz_services.save_fuzz_test import save_fuzz_test
from api.v1.services.fuzz_services.setup_environment import setup_environment
from common import logger
from common.send_prompt_to_llm import send_prompt_to_llm_async
from config.settings import LLM_MODEL_FUZZER


async def run_fuzzer(
    github_url: str, oauth_token: Optional[str] = None
) -> Dict[str, Union[Optional[str], str]]:
    """
    Executes the fuzzing process on a specified GitHub repository.

    This function sets up the environment, generates fuzzing prompts, sends them to a language model,
    extracts and saves the fuzz test, runs the fuzz test, and generates a report based on the results.

    Args:
        github_url (str): The GitHub repository URL.
        oauth_token (Optional[str]): The OAuth token for private repositories.

    Returns:
        Dict[str, Union[Optional[str], str]]: A dictionary containing the fuzz test, fuzz results, analysis, and any error encountered.
    """
    model = LLM_MODEL_FUZZER

    try:
        # 1. Setup the fuzzing environment
        project_dir, contract_folders, project_type, project_path = await setup_environment(
            github_url, oauth_token
        )
        logger.info(f"Project type: {project_type}")

        # 2. Generate fuzz prompts
        logger.info("Generating fuzz prompts")
        fuzz_prompts = await generate_fuzz_prompts(project_dir, contract_folders)

        # 3. Send fuzz prompts to LLM
        logger.info("Sending fuzz prompts to LLM")
        fuzz_response = await send_prompt_to_llm_async(model, fuzz_prompts)

        # 4. Extract fuzz test
        logger.info("Extracting fuzz test")
        fuzz_test = extract_fuzz_test(fuzz_response)

        # 5. Save fuzz test
        logger.info("Saving fuzz test")
        await save_fuzz_test(fuzz_test, project_dir, contract_folders)

        # 6. Run fuzz test
        logger.info("Running fuzz test")
        fuzz_results = await run_fuzz_file(project_dir)
        logger.info(f"Fuzz results: {fuzz_results}")

        # 7. Cleanup environment
        logger.info("Cleaning up environment")
        await cleanup_environment(project_path)

        # 8. Generate report prompt
        logger.info("Generating report prompt")
        report_prompt = await generate_report_prompt(fuzz_test, fuzz_results)

        # 9. Send report prompt to LLM
        logger.info("Sending report prompt to LLM")
        report_response = await send_prompt_to_llm_async(model, report_prompt)

        # 10. Convert the report to JSON
        report_json = {
            "fuzz_test": fuzz_test,
            "fuzz_results": fuzz_results,
            "analysis": report_response,
            "error": None,
        }

        return report_json
    except Exception as e:
        return {
            "fuzz_test": None,
            "fuzz_results": None,
            "analysis": None,
            "error": str(e),
        }
