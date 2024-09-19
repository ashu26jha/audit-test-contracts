import re
from typing import Optional

def validate_contract(contracts: str) -> Optional[str]:
    """
    Validates the Solidity contract structure and extracts the Solidity version.

    Args:
        contracts (str): The Solidity contract code.

    Returns:
        Optional[str]: The detected Solidity version if valid, else raises ValueError.
    """

    solidity_structure_pattern = re.compile(
        r'pragma solidity [\^\d.]+;[\s\S]*contract [A-Za-z0-9_]+ [\s\S]*{[\s\S]*}'
    )
    structure_match = solidity_structure_pattern.search(contracts)
    # NOTE: Is this necessary? Since we do not want to allow non-solidity code to be fuzzed.
    # but it quits in the run_fuzz function when this returns false.

    # if not structure_match:
    #     raise ValueError('Invalid contract structure.')
    # print("Contract is valid")

    # # Extract Solidity version from pragma
    # pragma_match = re.search(r'pragma solidity\s+([^;]+);', contracts)
    # if not pragma_match:
    #     raise ValueError('Pragma Solidity version not found in contracts.')
    
    # version_spec = pragma_match.group(1).strip()
    # # Extract the first version number (e.g., "^0.8.0" -> "0.8.0")
    # version_match = re.search(r'\d+\.\d+\.\d+', version_spec)
    # if not version_match:
    #     raise ValueError('Unable to parse Solidity version from pragma.')
    
    # solc_version = version_match.group(0)
    # print(f"Detected Solidity version: {solc_version}")

    return bool(structure_match)
