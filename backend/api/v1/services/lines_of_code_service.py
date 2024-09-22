import io
from typing import Dict

from pygount import SourceAnalysis


async def count_lines_of_code(flattened_contracts: str) -> Dict[str, int]:
    """
    Count the lines of code in the flattened Solidity contract using pygount.

    Args:
        flattened_contracts (str): The flattened Solidity contract as a string.

    Returns:
        Dict[str, int]: A dictionary containing different types of line counts.
    """
    # Create a file-like object from the string
    file_like_object = io.StringIO(flattened_contracts)

    # Analyze the code using pygount
    analysis = SourceAnalysis.from_file(
        "temp.sol",
        "solidity",
        file_handle=file_like_object,
    )

    return {
        "total_lines": analysis.code_count + analysis.documentation_count + analysis.empty_count,
        "code_lines": analysis.code_count,
        "comment_lines": analysis.documentation_count,
        "empty_lines": analysis.empty_count,
        "string_lines": analysis.string_count,
    }
