import io

from fastapi import HTTPException
from pygount import SourceAnalysis

from api.v1.models.scan import CodeAnalysisResult
from common import logger


async def count_lines_of_code(flattened_contracts: str) -> CodeAnalysisResult:
    return await _analyze_code(content=flattened_contracts, include_string_count=True)


async def analyze_file_content(
    content: str, filename: str, is_readme: bool = False
) -> CodeAnalysisResult:
    if is_readme:
        return await _count_characters(content)
    return await _analyze_code(content=content, filename=filename, include_string_count=False)


async def _count_characters(content: str) -> dict:
    """
    Count the number of characters in the content.

    Args:
        content: The content to analyze
    """
    try:
        return {
            "character_count": len(content),
            "non_whitespace_character_count": len(content.strip()),
        }
    except Exception as e:
        logger.exception(f"Failed to count characters: {str(e)}")
        raise HTTPException(status_code=500, detail="Internal Server Error")


async def _analyze_code(
    content: str,
    filename: str = "temp.sol",
    language: str = "solidity",
    include_string_count: bool = True,
) -> CodeAnalysisResult:
    """
    Analyze code content using pygount.

    Args:
        content: The source code content as string
        filename: Name of the file (used for language detection)
        language: Programming language of the content
        include_string_count: Whether to include string_lines in output
    """
    try:
        file_like_object = io.StringIO(content)
        analysis = SourceAnalysis.from_file(
            filename,
            language,
            file_handle=file_like_object,
        )

        result = {
            "total_lines": analysis.code_count
            + analysis.documentation_count
            + analysis.empty_count,
            "code_lines": analysis.code_count,
            "comment_lines": analysis.documentation_count,
            "empty_lines": analysis.empty_count,
        }

        if include_string_count:
            result["string_lines"] = analysis.string_count

        return result

    except Exception as e:
        logger.exception(f"Failed to analyze code content: {str(e)}")
        raise HTTPException(status_code=500, detail="Internal Server Error")
