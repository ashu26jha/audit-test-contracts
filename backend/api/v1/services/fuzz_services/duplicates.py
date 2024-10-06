from api.v1.services.fuzzing_service import run_fuzzer
from api.v1.schemas.fuzzer_schema import FuzzTestResult
from common.send_prompt_to_llm import send_prompt_to_llm_async
from typing import List, Dict

async def compare_with_llm(new_vulns: List[Dict], existing_vulns: List[Dict], LLM_MODEL: str) -> List[Dict]:
    """
    Sends the new and existing vulnerabilities to the LLM for comparison and returns unique findings.

    Args:
        new_vulns (List[Dict]): New vulnerabilities from the fuzzer.
        existing_vulns (List[Dict]): Existing vulnerabilities from the audit agent.

    Returns:
        List[Dict]: A list of unique vulnerabilities after LLM comparison.
    """
    # Prepare the prompt for the LLM
    prompt = f"""
    You are a smart contract security expert. Compare the following two lists of vulnerabilities and identify which ones are duplicates.

    New Vulnerabilities:
    {new_vulns}

    Existing Vulnerabilities:
    {existing_vulns}

    Please return a list of unique vulnerabilities from the new vulnerabilities, excluding any duplicates.
    """

    # Send the prompt to the LLM
    llm_response = await send_prompt_to_llm_async(LLM_MODEL, prompt)

    # Assuming the LLM returns a list of unique vulnerabilities
    unique_vulnerabilities = llm_response.get("unique_vulnerabilities", [])

    return unique_vulnerabilities