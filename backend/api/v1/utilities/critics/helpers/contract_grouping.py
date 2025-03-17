from typing import Awaitable, Callable, Dict, List, Tuple, TypeVar

from api.v1.utilities.critics.schema import IndexedFinding
from core.models.scan import Finding
from core.utils.logger import logger

T = TypeVar("T")


async def process_findings_by_contract_groups(
    findings: List[Finding],
    contract_contents: Dict[str, str],
    processor: Callable[[List[IndexedFinding], str], Awaitable[List[IndexedFinding]]],
    operation_name: str = "processing",
) -> List[Finding]:
    """
    Process findings by grouping them by their primary contract.

    This function:
    1. Groups findings by their primary contract (first contract in the Contracts list)
    2. For each group, processes the findings with the provided processor function
    3. Combines the results from all groups

    Args:
        findings: List of findings to process
        contract_contents: Dictionary mapping contract filenames to their source code
        processor: Async function that processes a batch of IndexedFinding objects with contract code
        operation_name: Name of the operation for logging

    Returns:
        List of processed findings
    """
    if not findings:
        return []

    logger.info(
        f"[{operation_name.upper()}] Processing {len(findings)} findings using contract-based grouping"
    )

    # Group findings by first contract in their Contracts list
    grouped_findings, contracts_code = group_findings_by_contract(findings, contract_contents)

    logger.info(f"[{operation_name.upper()}] Processing {len(grouped_findings)} contract groups")

    # Process each contract group
    processed_findings = []

    for primary_contract, group_findings in grouped_findings.items():
        if not group_findings:
            continue

        contract_code = contracts_code.get(primary_contract, "")
        logger.info(
            f"[{operation_name.upper()}] Processing group for {primary_contract} with {len(group_findings)} findings"
        )

        # Create indexed findings for this group
        indexed_group = [
            IndexedFinding(index=i, finding=finding) for i, finding in enumerate(group_findings)
        ]

        # Process this group
        processed_group = await processor(indexed_group, contract_code)

        # Convert back to Finding objects and add to result
        processed_findings.extend([item.finding for item in processed_group])

    logger.info(
        f"[{operation_name.upper()}] Contract-based processing complete: {len(processed_findings)} findings after processing"
    )
    return processed_findings


def group_findings_by_contract(
    findings: List[Finding], contract_contents: Dict[str, str]
) -> Tuple[Dict[str, List[Finding]], Dict[str, str]]:
    """
    Group findings by their primary contract and prepare contract code for each group.

    Args:
        findings: List of findings to group
        contract_contents: Dictionary mapping contract filenames to their source code

    Returns:
        Tuple of:
        - Dictionary mapping primary contracts to their findings
        - Dictionary mapping primary contracts to their relevant code
    """
    # 1. Group findings by first contract in their Contracts list
    grouped_by_contract = {}
    for finding in findings:
        if finding.Contracts:  # Ensure there's at least one contract
            primary_contract = finding.Contracts[0]
            if primary_contract not in grouped_by_contract:
                grouped_by_contract[primary_contract] = []
            grouped_by_contract[primary_contract].append(finding)

    # 2. Extract code for each contract group
    contracts_code_by_group = {}
    for primary_contract, group_findings in grouped_by_contract.items():
        # Collect all unique contracts mentioned in this group
        all_contracts = set()
        for finding in group_findings:
            all_contracts.update(finding.Contracts)

        # Extract code for all contracts in this group
        group_code = ""
        for contract in all_contracts:
            if contract in contract_contents:
                group_code += f"// File: {contract}\n"
                group_code += contract_contents[contract]
                group_code += "\n\n"

        contracts_code_by_group[primary_contract] = group_code.strip()

    return grouped_by_contract, contracts_code_by_group
