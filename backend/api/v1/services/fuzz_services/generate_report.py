from typing import List

from api.v1.schemas.context_scan_schema import FindingList
from common import logger
from common.parse_llm_response import parse_model_response
from common.send_prompt_to_llm import send_prompt_to_llm_async
from config.prompts.fuzzer_prompts import REPORT_PROMPT
from config.settings import LLM_MODEL_MEDIUM


async def generate_report(
    fuzz_test: str, fuzz_results: str, contract_folders: List[str]
) -> FindingList:
    """
    Generates a report based on the provided fuzz test and its execution results.
    The function formats the input data into a prompt for the LLM and retrieves
    the generated report findings.

    Args:
        fuzz_test (str): The content of the fuzz test to be reported on.
        fuzz_results (str): The results of the fuzz test execution, detailing outcomes.
        contract_folders (List[str]): The folders containing the contract files relevant to the fuzz test.

    Returns:
        FindingList: The generated report findings parsed from the LLM's response.
    """
    logger.info("Generating fuzzing report...")

    try:
        # Generate prompt
        report_prompt = REPORT_PROMPT.format(
            fuzz_test=fuzz_test, results=fuzz_results, contract_code=contract_folders
        )

        # Send prompt to LLM
        report_response = await send_prompt_to_llm_async(LLM_MODEL_MEDIUM, report_prompt)

        # Parse LLM response
        report = parse_model_response(report_response, FindingList)

        return report
    except Exception as e:
        logger.error(f"Error generating report: {str(e)}")
