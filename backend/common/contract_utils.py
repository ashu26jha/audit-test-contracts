from typing import List, Set

from api.v1.schemas.context_scan_schema import Finding


def normalize_contract_name(contract_path: str) -> str:
    """
    Normalizes a contract name by:
    1. Taking only the filename from the path
    2. Converting to lowercase for case-insensitive comparison

    Args:
        contract_path (str): Full contract path or name (e.g., "contracts/MyContract.sol" or "MyContract.sol")

    Returns:
        str: Normalized contract name (e.g., "mycontract.sol")
    """
    return contract_path.split("/")[-1].lower()


def filter_by_contracts(
    findings: List[Finding], selected_contracts: List[str], contract_field: str = "Contracts"
) -> List[Finding]:
    """
    Filters findings to include only those in selected contracts.
    Uses case-insensitive matching and handles path variations.

    Args:
        findings: List of findings (Pydantic models)
        selected_contracts: List of contract paths/names to filter by
        contract_field: Name of the field containing contract names in findings

    Returns:
        List of filtered findings
    """
    if not selected_contracts:
        return findings

    selected_names: Set[str] = {
        normalize_contract_name(contract) for contract in selected_contracts
    }

    return [
        finding
        for finding in findings
        if any(
            normalize_contract_name(contract) in selected_names
            for contract in getattr(finding, contract_field)
        )
    ]
