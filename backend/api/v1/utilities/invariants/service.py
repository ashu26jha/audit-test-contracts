from typing import Dict, List, Optional

from langfuse.decorators import observe

from api.v1.common.invariants_helpers import flatten_contracts
from api.v1.utilities.invariants.schema import Invariant, InvariantsResponse
from config.prompts.invariants_prompts import INVARIANTS_PROMPT
from config.settings import LLM_SCAN_3
from core.llm.send_prompt_to_llm import send_prompt_to_llm_async
from core.utils.logger import logger


@observe(name="invariants_generation")
async def generate_invariants(
    contracts_in_scope: List[str],
    flattened_contracts: str,
    max_invariants: Optional[int] = 50,
    docs: Optional[str] = None,
    selected_invariants: Optional[List[Invariant]] = None,
    contract_contents: Optional[Dict[str, str]] = None,
) -> InvariantsResponse:
    """
    Generates invariants for based on the provided project structure, flattened contracts,
    and optional Slither analysis output. The function formats the input data into a prompt for the LLM
    and retrieves the generated invariants.
    Non-critical operation that will not affect the scan when it fails.

    Args:
        contracts_in_scope (List[str]): List of contract file paths to analyze.
        flattened_contracts (str): The complete Solidity code of the contracts, flattened into a single string.
        max_invariants (int): Invariants to be generated
        docs (str): Optional docs if available
        selected_invariants (List[Invariant]): Optional list of invariants to be used for the prompt
        contract_contents (Dict[str, str]): Optional dictionary of contract contents
    Returns:
        InvariantsResponse: The generated invariants parsed from the LLM's response.
                           Returns empty invariants list on failure.
    """
    logger.info("[Invariants] Generating invariants with LLM...")

    try:
        has_selected_invariants = selected_invariants and len(selected_invariants) > 0
        filtered_contracts_in_scope = []
        if has_selected_invariants:
            # Filter out contracts that exist in selected_invariants
            filtered_contracts_in_scope = [
                contract
                for contract in contracts_in_scope
                if not any(contract == invariant.path for invariant in (selected_invariants or []))
            ]
        else:
            filtered_contracts_in_scope = contracts_in_scope

        if len(filtered_contracts_in_scope) == 0:
            logger.info(
                "[Invariants] All contracts already have invariants selected, using existing invariants only"
            )
            selected_invariants_dicts = [inv.model_dump() for inv in (selected_invariants or [])]
            return InvariantsResponse(invariants=selected_invariants_dicts)

        # Flatten the contracts that match the paths in selected_invariants
        if contract_contents and has_selected_invariants:
            flattened_contracts = flatten_contracts(contract_contents, selected_invariants)

        # Format the contracts_in_scope list for the prompt
        formatted_contracts = "\n".join(filtered_contracts_in_scope)

        # Generate the invariant prompt
        invariant_prompt = INVARIANTS_PROMPT.format(
            max_invariants=max_invariants,
            contracts_in_scope=formatted_contracts,
            flattened_contracts=flattened_contracts,
            docs=docs,
        )

        # Send the invariant prompt to the LLM
        invariants = await send_prompt_to_llm_async(
            model_type=LLM_SCAN_3,
            messages=invariant_prompt,
            response_model=InvariantsResponse,
        )
        # Combine selected_invariants with new invariants if they exist
        if has_selected_invariants:
            # Convert each invariant to a dictionary before combining
            selected_invariants_dicts = [inv.model_dump() for inv in selected_invariants]
            new_invariants_dicts = [inv.model_dump() for inv in invariants.invariants]

            # Combine the dictionaries
            all_invariants_dicts = selected_invariants_dicts + new_invariants_dicts

            # Create new InvariantsResponse with the combined dictionaries
            combined_invariants = InvariantsResponse(invariants=all_invariants_dicts)
            logger.info(
                f"[Invariants] {len(combined_invariants.invariants)} total invariants after combining"
            )
            return combined_invariants

        # Check if invariants were generated
        if not invariants or not invariants.invariants:
            logger.warning("[Invariants] LLM returned empty invariants list")
            return InvariantsResponse(invariants=[])

        logger.info(f"[Invariants] {len(invariants.invariants)} invariants generated successfully")
        return invariants

    except Exception as e:
        logger.error(f"[Invariants] Error generating invariants: {str(e)}", exc_info=True)
        return InvariantsResponse(invariants=[])
