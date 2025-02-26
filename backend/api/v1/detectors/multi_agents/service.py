import asyncio
import os
from typing import Dict, List, Optional

from api.v1.detectors.context_scan.schema import FindingList
from api.v1.detectors.multi_agents.helper.process_entry_point import process_entry_point
from api.v1.detectors.multi_agents.schema import EntryPoint
from api.v1.utilities.ast_tree.helpers.solidity_files_storage import SolidityFileStorage
from api.v1.utilities.ast_tree.schema import ProjectAST
from core.models.scan import Finding
from core.utils.logger import logger

from .helper.extract_entry_points import extract_entry_points

MAX_CONCURRENT = 10


async def run_multi_agent(
    contracts_in_scope: List[str],
    ast_tree: ProjectAST,
    project_dir: str,
    docs: Optional[str] = None,
    max_concurrent: int = MAX_CONCURRENT,
) -> FindingList:
    """
    Orchestrates the multi-agents analysis process.

    Args:
        contracts_in_scope: List of contract file paths to analyze (e.g. ["src/ContestManager.sol"])
        flattened_contracts: The complete Solidity code of the contracts
        ast_tree: AST tree containing contract dependencies
        project_dir: The root directory of the project
        max_concurrent: Maximum number of concurrent agent groups

    Returns:
        List of validated findings from all agent groups
    """
    try:
        # 1. Extract entry points
        entry_points = await extract_entry_points(contracts_in_scope, ast_tree)
        if not entry_points:
            logger.warning("[MultiAgents] No entry points found to analyze")
            return FindingList(findings=[])

        logger.info(f"[MultiAgents] Processing {len(entry_points)} entry points...")

        # Initialize storage helper with the project root directory
        storage = SolidityFileStorage(project_dir)

        # Create a mapping of contract names to their full paths
        contract_paths: Dict[str, str] = {
            os.path.basename(path): path for path in contracts_in_scope
        }

        # 2. Process entry points concurrently with semaphore
        iterations_per_entrypoint = _calculate_iterations_per_entrypoint(entry_points)
        sem = asyncio.Semaphore(max_concurrent)

        async def process_with_semaphore(entry_point: EntryPoint):
            async with sem:
                # Get the contract containing the entry point
                contract_name = os.path.basename(entry_point.contract_name)
                contract_ast = ast_tree.contracts.get(contract_name)
                if not contract_ast:
                    logger.error(f"[MultiAgents] Contract {contract_name} not found in AST tree")
                    return []

                # Get the full path from our mapping
                contract_path = contract_paths.get(contract_name)
                if not contract_path:
                    logger.error(f"[MultiAgents] Could not find path for contract: {contract_name}")
                    return []

                # Read the main contract using the full path
                main_contract = storage.read_contract(contract_path)
                if not main_contract:
                    logger.error(f"[MultiAgents] Could not read contract file: {contract_path}")
                    return []

                # Get and read all dependencies
                dependency_contents = []
                processed_deps = set()  # Track processed dependencies to avoid duplicates

                for dep in contract_ast.dependencies:
                    # Skip if already processed
                    if dep in processed_deps:
                        continue

                    processed_deps.add(dep)

                    # Resolve the dependency path using our helper
                    dep_path = _resolve_dependency_path(dep, contract_paths, project_dir)
                    dep_content = storage.read_contract(dep_path)

                    if dep_content:
                        dependency_contents.append(dep_content)
                    else:
                        logger.warning(f"[MultiAgents] Could not read dependency: {dep_path}")

                # Combine main contract with its dependencies
                relevant_contracts = "\n\n".join([main_contract] + dependency_contents)

                # Process the entry point with only relevant contracts
                return await process_entry_point(
                    relevant_contracts, entry_point, iterations_per_entrypoint, docs
                )

        # Create tasks for concurrent processing
        tasks = [process_with_semaphore(ep) for ep in entry_points]

        # 3. Gather results, ignoring individual failures
        all_findings: List[Finding] = []
        for task in asyncio.as_completed(tasks):
            try:
                findings = await task
                all_findings.extend(findings)
            except Exception as e:
                logger.error(f"[MultiAgents] Error processing task: {str(e)}")
                continue

        # 4. Sort by severity and return results
        severity_order = {"High": 0, "Medium": 1, "Low": 2, "Info": 3, "Best Practices": 4}
        final_findings = sorted(all_findings, key=lambda x: severity_order[x.Severity])
        return FindingList(findings=final_findings)

    except Exception as e:
        logger.error(f"[MultiAgents] Critical error in multi-agents process: {str(e)}")
        raise RuntimeError(f"Multi-agents analysis failed: {str(e)}")


def _calculate_iterations_per_entrypoint(entry_points: List[EntryPoint]) -> int:
    """
    Calculate the number of iterations per entry point based on the number of entry points.
    """
    if len(entry_points) > 20:
        return 1
    return 2


def _resolve_dependency_path(
    dependency_name: str, contract_paths: Dict[str, str], project_dir: str
) -> str:
    """
    Resolve a dependency path to a format compatible with SolidityFileStorage.

    This function finds the appropriate path for a dependency, prioritizing
    paths in the contract_paths mapping, which are already in the correct format
    for SolidityFileStorage.read_contract().

    Args:
        dependency_name: The name or path of the dependency
        contract_paths: Dictionary mapping contract names to their paths
        project_dir: The root directory of the project

    Returns:
        The resolved path suitable for SolidityFileStorage.read_contract()
    """
    # Try direct mapping from basename first (most common case)
    # This is the safest option as these paths are already in the format
    # expected by SolidityFileStorage
    basename = os.path.basename(dependency_name)
    if basename in contract_paths:
        return contract_paths[basename]

    # Since SolidityFileStorage expects paths relative to project_root,
    # we return the dependency_name as is (don't try to make it absolute)
    # SolidityFileStorage.read_contract will handle the path resolution
    return dependency_name
