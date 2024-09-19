import asyncio
from pathlib import Path
from api.v1.prompts.fuzzer_prompts import REPORT_PROMPT

async def generate_report_prompt(fuzz_test: str, fuzz_results: str) -> str:
    """
    Generates the report prompt using the provided fuzz test and results.

    Args:
        fuzz_test (str): The content of the fuzz test.
        fuzz_results (str): The results of the fuzz test execution.

    Returns:
        str: The generated report prompt.
    """
    return REPORT_PROMPT.format(
        fuzz_test=fuzz_test,
        results=fuzz_results
    )
