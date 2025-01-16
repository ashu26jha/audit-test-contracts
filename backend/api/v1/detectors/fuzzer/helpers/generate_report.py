from typing import List

from api.v1.detectors.context_scan.schema import FindingList
from api.v1.detectors.fuzzer.schema import InvariantsList
from config.prompts.fuzzer_prompts import REPORT_PROMPT
from config.settings import LLM_UTILITY
from core.llm.send_prompt_to_llm import send_prompt_to_llm_async
from core.utils.logger import logger


async def generate_report(
    invariants: InvariantsList, fuzz_test: str, fuzz_results: str, flattened_contracts: List[str]
) -> FindingList:
    """
    Generates a report based on the provided fuzz test and its execution results.
    The function formats the input data into a prompt for the LLM and retrieves
    the generated report findings.

    Args:
        invariants (InvariantsList): The invariants to be reported on.
        fuzz_test (str): The content of the fuzz test to be reported on.
        fuzz_results (str): The results of the fuzz test execution, detailing outcomes.
        flattened_contracts: The flattened contracts from the project structure.

    Returns:
        FindingList: The generated report findings parsed from the LLM's response.
    """
    logger.info("Generating fuzzing report...")

    # Format invariants as a string list
    invariants_formatted = "\n".join(f"- {invariant}" for invariant in invariants.invariants)

    # Generate prompt
    report_prompt = REPORT_PROMPT.format(
        invariants=invariants_formatted,
        fuzz_test=fuzz_test,
        results=fuzz_results,
        contract_code=flattened_contracts,
    )

    # Send prompt to LLM
    report = await send_prompt_to_llm_async(
        model_type=LLM_UTILITY,
        messages=report_prompt,
        response_model=FindingList,
    )

    logger.info(f"Report generated with {len(report.findings)} findings.")
    return report
