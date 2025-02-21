from typing import List

from api.v1.utilities.invariants.schema import InvariantsResponse
from config.prompts.invariants_prompts import INVARIANTS_PROMPT
from config.settings import LLM_SCAN_3
from core.llm.send_prompt_to_llm import send_prompt_to_llm_async
from core.utils.logger import logger


async def generate_invariants(
    contracts_in_scope: List[str],
    flattened_contracts: str,
) -> InvariantsResponse:
    """
    Generates invariants for based on the provided project structure, flattened contracts,
    and optional Slither analysis output. The function formats the input data into a prompt for the LLM
    and retrieves the generated invariants.
    Non-critical operation that will not affect the scan when it fails.

    Args:
        contracts_in_scope (List[str]): List of contract file paths to analyze.
        flattened_contracts (str): The complete Solidity code of the contracts, flattened into a single string.

    Returns:
        InvariantsResponse: The generated invariants parsed from the LLM's response.
    """
    logger.info("[Invariants] Generating invariants with LLM...")

    try:
        # Format the contracts_in_scope list for the prompt
        formatted_contracts = "\n".join(contracts_in_scope)

        # Generate the invariant prompt
        invariant_prompt = INVARIANTS_PROMPT.format(
            contracts_in_scope=formatted_contracts,
            flattened_contracts=flattened_contracts,
        )

        # Send the invariant prompt to the LLM
        invariants = await send_prompt_to_llm_async(
            model_type=LLM_SCAN_3,
            messages=invariant_prompt,
            response_model=InvariantsResponse,
        )

        logger.info(f"[Invariants] {len(invariants.invariants)} invariants generated successfully")
        return invariants

    except Exception as e:
        logger.error(f"[Invariants] Error generating invariants: {e}")
        return InvariantsResponse(invariants=[])
