import io

from pygount import SourceAnalysis

from core.models.scan import CodeAnalysisResult
from core.utils.errors import ContractError
from core.utils.logger import logger


async def count_lines_of_code(flattened_contracts: str) -> CodeAnalysisResult:
    """
    Count lines of code in flattened contracts.

    Args:
        flattened_contracts: The flattened contract code

    Returns:
        CodeAnalysisResult with line counts
    """
    # Check if this is Cairo code by looking for common Cairo patterns
    is_cairo = (
        "use starknet::" in flattened_contracts or "#[starknet::contract]" in flattened_contracts
    )

    if is_cairo:
        return await _count_lines_manually(flattened_contracts)
    else:
        return await _analyze_code(content=flattened_contracts, include_string_count=True)


async def analyze_file_content(
    content: str, filename: str, is_readme: bool = False
) -> CodeAnalysisResult:
    if is_readme:
        return await _count_characters(content)

    # Determine language based on file extension
    if filename.lower().endswith(".cairo"):
        # For Cairo files, use a manual line counting approach
        return await _count_lines_manually(content)

    # For Solidity files, use pygount
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
        raise ContractError(message="Failed to count characters", details={"error": str(e)}) from e


async def _count_lines_manually(content: str) -> CodeAnalysisResult:
    """
    Count lines manually for file types not supported by pygount.

    Args:
        content: The content to analyze
    """
    try:
        lines = content.split("\n")
        total_lines = len(lines)

        # Count empty lines
        empty_lines = sum(1 for line in lines if line.strip() == "")

        # Count comment lines (simple heuristic)
        comment_lines = sum(
            1 for line in lines if line.strip().startswith("//") or line.strip().startswith("#")
        )

        # Code lines are the remaining lines
        code_lines = total_lines - empty_lines - comment_lines

        return CodeAnalysisResult(
            total_lines=total_lines,
            code_lines=code_lines,
            comment_lines=comment_lines,
            empty_lines=empty_lines,
            string_lines=0,  # Not counting string lines in manual mode
        )
    except Exception as e:
        logger.exception(f"Failed to count lines manually: {str(e)}")
        raise ContractError(
            message="Failed to count lines manually", details={"error": str(e)}
        ) from e


async def _analyze_code(
    content: str,
    filename: str = "temp.sol",
    language: str = None,
    include_string_count: bool = True,
) -> CodeAnalysisResult:
    """
    Analyze code content using pygount.

    Args:
        content: The source code content as string
        filename: Name of the file (used for language detection)
        language: Programming language of the content (if None, auto-detect from filename)
        include_string_count: Whether to include string_lines in output
    """
    try:
        # Determine language if not provided
        if language is None:
            if filename.lower().endswith(".sol"):
                language = "solidity"
            else:
                # Let pygount auto-detect for other file types
                language = None

        # Normalize line endings to LF before analysis
        normalized_content = content.replace("\r\n", "\n")
        file_like_object = io.StringIO(normalized_content)

        try:
            analysis = SourceAnalysis.from_file(
                filename,
                language,
                file_handle=file_like_object,
            )

            result = CodeAnalysisResult(
                total_lines=analysis.line_count,
                code_lines=analysis.code_count,
                comment_lines=analysis.documentation_count,
                empty_lines=analysis.empty_count,
                string_lines=analysis.string_count if include_string_count else 0,
            )

            return result
        except AssertionError:
            # If pygount fails (likely due to unsupported language), fall back to manual counting
            logger.warning(f"Pygount failed to analyze {filename}, falling back to manual counting")
            file_like_object.seek(0)  # Reset file pointer
            return await _count_lines_manually(file_like_object.read())

    except Exception as e:
        logger.exception(f"Failed to analyze code content: {str(e)}")
        raise ContractError(
            message="Failed to analyze code content", details={"error": str(e)}
        ) from e
