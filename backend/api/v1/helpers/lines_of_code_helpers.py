import io
from typing import Dict

from fastapi import HTTPException
from pygount import SourceAnalysis

from common import logger


async def count_lines_of_code(flattened_contracts: str) -> Dict[str, int]:
    try:
        file_like_object = io.StringIO(flattened_contracts)
        analysis = SourceAnalysis.from_file(
            "temp.sol",
            "solidity",
            file_handle=file_like_object,
        )
        return {
            "total_lines": analysis.code_count
            + analysis.documentation_count
            + analysis.empty_count,
            "code_lines": analysis.code_count,
            "comment_lines": analysis.documentation_count,
            "empty_lines": analysis.empty_count,
            "string_lines": analysis.string_count,
        }
    except Exception as e:
        logger.exception(f"Failed to count lines of code: {str(e)}")
        raise HTTPException(status_code=500, detail="Internal Server Error")
