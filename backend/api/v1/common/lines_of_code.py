import io

from fastapi import HTTPException
from pygount import SourceAnalysis

from core.models.scan import CodeAnalysisResult
from core.utils.logger import logger


async def count_lines_of_code(flattened_contracts: str) -> CodeAnalysisResult:
    return await _analyze_code(content=flattened_contracts, include_string_count=True)


async def analyze_file_content(
    content: str, filename: str, is_readme: bool = False
) -> CodeAnalysisResult:
    if is_readme:
        return await _count_characters(content)
    return await _analyze_code(content=content, filename=filename, include_string_count=False)


async def _count_characters(content: str) -> CodeAnalysisResult:
    """
    Count the number of characters in the content.

    Args:
        content: The content to analyze
    """
    try:
        return CodeAnalysisResult(
            total_lines=0,
            code_lines=0,
            comment_lines=0,
            empty_lines=0,
            string_lines=0,
            character_count=len(content),
            non_whitespace_character_count=len(content.strip()),
        )
    except Exception as e:
        logger.exception(f"Failed to count characters: {str(e)}")
        raise HTTPException(status_code=500, detail="Internal Server Error") from e


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
        # Normalize line endings to LF before analysis
        normalized_content = content.replace("\r\n", "\n")
        file_like_object = io.StringIO(normalized_content)
        analysis = SourceAnalysis.from_file(
            filename,
            language,
            file_handle=file_like_object,
        )

        result = CodeAnalysisResult(
            total_lines=analysis.code_count + analysis.documentation_count + analysis.empty_count,
            code_lines=analysis.code_count,
            comment_lines=analysis.documentation_count,
            empty_lines=analysis.empty_count,
            string_lines=analysis.string_count if include_string_count else 0,
        )

        return result

    except Exception as e:
        logger.exception(f"Failed to analyze code content: {str(e)}")
        raise HTTPException(status_code=500, detail="Internal Server Error") from e
