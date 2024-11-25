from api.v1.schemas.fuzzer_schema import InvariantsList
from common import logger
from common.profiles import Profiles
from common.send_prompt_to_llm import send_prompt_to_llm_async
from config.prompts.fuzzer_prompts import FUZZER_INVARIANT_PROMPT
from config.settings import LLM_MODEL_BEST_2


async def generate_invariants(
    detected_profile: Profiles,
    project_structure: str,
    flattened_contracts: str,
    selected_contracts_code: str,
) -> InvariantsList:
    """
    Generates invariants for fuzz testing based on the provided project structure, flattened contracts,
    and optional Slither analysis output. The function formats the input data into a prompt for the LLM
    and retrieves the generated invariants.

    Args:
        detected_profile (Profiles): The detected profile, if any, used for context in generation.
        project_structure (str): The structure of the project, detailing the organization of contracts.
        flattened_contracts (str): The complete Solidity code of the contracts, flattened into a single string.
        selected_contracts_code (str): The selected contracts to be included in the prompt.
    Returns:
        InvariantsList: The generated invariants parsed from the LLM's response.
    """
    logger.info("Generating invariants with LLM...")

    model = LLM_MODEL_BEST_2

    # Generate the invariant prompt
    invariant_prompt = FUZZER_INVARIANT_PROMPT.format(
        project_structure=project_structure,
        contract_code=flattened_contracts,
        selected_contracts=selected_contracts_code,
    )

    # Send the invariant prompt to the LLM
    invariants = await send_prompt_to_llm_async(
        model, invariant_prompt, response_model=InvariantsList
    )

    logger.info(f"{len(invariants.invariants)} invariants generated")
    return invariants
