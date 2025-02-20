from dataclasses import dataclass
from typing import Dict, List
from uuid import UUID

from api.v1.common.lines_of_code import count_lines_of_code
from api.v1.utilities.etherscan.service import EtherscanService
from core.db.repositories.scan import ScanRepository
from core.utils.logger import logger


@dataclass
class ContractSourceInfo:
    """Data class to hold contract source information from blockchain"""

    flattened_contracts: str
    contract_files: List[str]
    contracts_dict: Dict[str, any]


async def get_contracts_per_address(
    scan_id: UUID,
    contract_address: str,
    chain_id: int,
) -> ContractSourceInfo:
    """
    Retrieves and processes contract source code from Etherscan.

    Args:
        scan_id: UUID of the current scan
        contract_address: Contract address to fetch source for
        chain_id: Chain ID where contract is deployed

    Returns:
        ContractSourceInfo object containing processed source code and metadata

    Raises:
        Exception: If contract source cannot be fetched or validated
    """
    try:
        # Fetch contract source code from Etherscan
        contracts_dict = await EtherscanService.get_contract_source(contract_address, chain_id)

        if not contracts_dict:
            raise ValueError(
                f"Could not fetch source code for contract {contract_address} on chain {chain_id}. "
                "Contract might not be verified."
            )

        # Flatten contracts
        flattened_contracts = ""
        for _, contract in contracts_dict.items():
            flattened_contracts += contract.content

        if not flattened_contracts.strip():
            raise ValueError(f"No source code content found for contract {contract_address}")

        # Get contract files from the contracts dictionary
        contract_files = list(contracts_dict.keys())

        # Count lines of code
        lines_of_code = await count_lines_of_code(flattened_contracts)
        await ScanRepository.update_scan_lines_of_code(scan_id, lines_of_code)

        return ContractSourceInfo(
            flattened_contracts=flattened_contracts,
            contract_files=contract_files,
            contracts_dict=contracts_dict,
        )

    except Exception as e:
        logger.exception(
            f"Error retrieving contract source for {contract_address} on chain {chain_id}: {str(e)}"
        )
        raise
