import re

from api.v1.utilities.etherscan.helpers.remove_external_imports import remove_external_imports
from api.v1.utilities.etherscan.schema import ContractSourceCode, ContractSourceCodeResponse
from core.utils import logger
from core.utils.token_count import count_tokens


def parse_source_code(source_code: str) -> ContractSourceCodeResponse:
    """
    Parse the source code returned by Etherscan API.
    Extracts .sol files and their contents from JSON format.
    Returns an empty dictionary if parsing fails.

    Args:
        source_code: Source code string from Etherscan

    Returns:
        ContractSourceCodeResponse: Mapping of .sol file names to their content and token length
    """
    try:
        pattern = r'"(@?[^"]+\.sol)":\s*{\s*"content":\s*"((?:\\.|[^"\\])*?)"'
        matches = re.finditer(pattern, source_code)

        result = {}

        for match in matches:
            contract_name = match.group(1)
            contract_content = match.group(2)
            contract_content = (
                contract_content.replace("\\n", "\n").replace("\\r", "\r").replace('\\"', '"')
            )
            token_length = count_tokens(contract_content)
            result[contract_name] = ContractSourceCode(
                content=contract_content, token_length=token_length
            )

        if not result:
            logger.warning("[Etherscan] No contracts found in source code")

        return result
    except Exception as e:
        logger.error(f"[Etherscan] Error parsing source code: {str(e)}")
        return {}


async def remove_external_libraries(
    source_code: ContractSourceCodeResponse,
) -> ContractSourceCodeResponse:
    """
    Remove external libraries from the source code

    Args:
        source_code: Dictionary mapping file names to their content and token length

    Returns:
        ContractSourceCodeResponse: Cleaned source code without external libraries
    """
    try:
        logger.info(f"[Etherscan] Total tokens in source code: {count_tokens(str(source_code))}")

        # First stage cleaning
        cleaned_contracts = first_stage_cleaning(source_code)
        logger.info(
            f"[Etherscan] Total tokens after first stage cleaning: {calculate_total_tokens(cleaned_contracts)}"
        )

        # Second stage cleaning
        cleaned_contracts = await remove_external_imports(cleaned_contracts)
        logger.info(
            f"[Etherscan] Total tokens after second stage cleaning: {calculate_total_tokens(cleaned_contracts)}"
        )

        return cleaned_contracts
    except Exception as e:
        logger.error(f"[Etherscan] Error cleaning external libraries: {str(e)}")
        return source_code


def first_stage_cleaning(source_code: ContractSourceCodeResponse) -> ContractSourceCodeResponse:
    """
    First stage cleaning of the source code - removes external library files

    Args:
        source_code: Dictionary mapping file names to their content and token length

    Returns:
        ContractSourceCodeResponse: Source code without external library files
    """
    try:
        external_libs = [
            key for key in source_code.keys() if key.startswith("@") or "interfaces" in key
        ]
        return {k: v for k, v in source_code.items() if k not in external_libs}
    except Exception as e:
        logger.error(f"[Etherscan] Error in first stage cleaning: {str(e)}")
        return source_code


def calculate_total_tokens(source_code: ContractSourceCodeResponse) -> int:
    """Calculate total tokens in source code."""
    try:
        return sum(contract.token_length for contract in source_code.values())
    except Exception as e:
        logger.error(f"[Etherscan] Error calculating total tokens: {str(e)}")
        return 0
