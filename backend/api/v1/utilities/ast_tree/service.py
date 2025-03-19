import asyncio
import os
from typing import List, Optional

from langfuse.decorators import observe

from api.v1.utilities.ast_tree.helpers.solidity_files_storage import SolidityFileStorage
from api.v1.utilities.ast_tree.schema import ContractAST, ProjectAST
from config.prompts.ast_prompt import AST_PROMPT, CAIRO_AST_PROMPT
from config.settings import LLM_UTILITY
from core.llm.send_prompt_to_llm import send_prompt_to_llm_async
from core.utils.logger import logger


@observe(name="genrate_ast")
async def generate_ast_per_contract(
    filename: str, file_path: str, contracts_in_scope: List[str]
) -> Optional[ContractAST]:
    """
    Generates an AST-like structure for a single contract, reading code from disk.
    Supports both Solidity and Cairo contracts.

    Args:
        filename (str): The contract filename.
        file_path (str): Path to the contract file.
        contracts_in_scope (List[str]): List of all contracts in scope for reference.

    Returns:
        Optional[ContractAST]: The structured AST representation for this contract, or None if generation fails.
    """
    try:
        # Read contract code from disk
        with open(file_path, "r", encoding="utf-8") as f:
            contract_code = f.read()

        # Format the contracts in scope as a string
        contracts_str = "\n".join(contracts_in_scope)

        # Determine contract language based on file extension
        is_cairo = filename.lower().endswith(".cairo")

        # Select the appropriate prompt template
        prompt_template = CAIRO_AST_PROMPT if is_cairo else AST_PROMPT
        logger.info(f"[AST] Using {'Cairo' if is_cairo else 'Solidity'} AST prompt for {filename}")

        # Format the prompt with contract-specific information
        ast_prompt = prompt_template.format(
            contracts_in_scope=contracts_str,
            flattened_contracts=contract_code,
        )

        contract_ast = await send_prompt_to_llm_async(
            model_type=LLM_UTILITY,
            messages=ast_prompt,
            response_model=ContractAST,
        )

        return contract_ast

    except Exception as e:
        logger.error(f"[AST] Error generating AST for {filename}: {e}")
        return None  # Return None to indicate failure


async def generate_ast_for_project(repo_path: str, contracts: List[str]) -> ProjectAST:
    """
    Generates an AST-like structure for the entire project by calling generate_ast_per_contract
    for each contract in parallel. Supports both Solidity and Cairo contracts.

    Args:
        repo_path (str): The base path of the cloned project.
        contracts (List[str]): List of contract file paths relative to repo_path.

    Returns:
        ProjectAST: The structured AST representation of the entire project.
    """
    logger.info(f"[AST] Generating AST for {len(contracts)} contracts from disk...")

    storage = SolidityFileStorage(repo_path)

    # Process each contract in parallel
    async def process_contract(contract_path: str):
        file_path = storage.get_contract_path(contract_path)
        # Extract filename from path for the AST tree structure
        filename = os.path.basename(contract_path)
        return filename, await generate_ast_per_contract(
            filename, file_path, contracts_in_scope=contracts
        )

    results = await asyncio.gather(
        *(process_contract(contract_path) for contract_path in contracts)
    )

    # Filter out failures and build the final ProjectAST
    valid_contracts = {filename: ast for filename, ast in results if ast is not None}

    if not valid_contracts:
        logger.warning("[AST] No valid ASTs were generated for any contracts.")

    project_ast = ProjectAST(contracts=valid_contracts)

    logger.info(f"[AST] Final AST generated with {len(project_ast.contracts)} contracts.")
    return project_ast
