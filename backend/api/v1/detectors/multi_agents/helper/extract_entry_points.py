from typing import List

from langfuse.decorators import observe

from api.v1.detectors.multi_agents.schema import EntryPoint, EntryPointResponse
from config.prompts.multiagent_prompts import ENTRY_POINTS_PROMPT
from config.settings import LLM_SCAN_3
from core.llm.send_prompt_to_llm import send_prompt_to_llm_async
from core.utils.logger import logger


@observe(name="entry_points_extraction")
async def extract_entry_points(contracts_in_scope: List[str], ast_tree: str) -> List[EntryPoint]:
    """
    Uses an LLM to extract entry points from the smart contracts.

    Args:
        contracts_in_scope: List of contract file paths to analyze
        flattened_contracts: The complete Solidity code of the contracts, flattened into a single string

    Returns:
        List of identified entry points
    """
    logger.info("[MultiAgent] Extracting entry points from contracts...")

    try:
        # Generate the entry point prompt
        entry_point_prompt = ENTRY_POINTS_PROMPT.format(
            contracts_in_scope=contracts_in_scope,
            ast_tree=ast_tree,
        )

        # Send the invariant prompt to the LLM
        response = await send_prompt_to_llm_async(
            model_type=LLM_SCAN_3,
            messages=entry_point_prompt,
            response_model=EntryPointResponse,
        )

        logger.info(
            f"[MultiAgent] {len(response.entry_points)} entry points extracted successfully"
        )
        return response.entry_points

    except Exception as e:
        logger.error(f"[MultiAgent] Error extracting entry points: {e}")
        return []
