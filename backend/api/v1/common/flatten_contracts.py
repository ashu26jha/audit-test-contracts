import os
from typing import List

from fastapi import HTTPException

from api.v1.common.lines_of_code import count_lines_of_code
from core.models.scan import CodeAnalysisResult
from core.utils.logger import logger


async def flatten_and_count_contracts(
    contract_files: List[str],
    project_dir: str,
) -> tuple[str, CodeAnalysisResult]:
    """
    Flattens contract files and counts the lines of code from the provided repository directory.
    Used by audit_agent_service after repository is cloned.

    Args:
        contract_files (List[str]): List of contract files to flatten
        project_dir (str): Path to the cloned repository directory

    Returns:
        str: Concatenated contract code with file headers,
        CodeAnalysisResult: count of lines

    Raises:
        HTTPException: If project_dir is invalid or files are not found
    """
    if not project_dir or not os.path.exists(project_dir):
        logger.error("Repository directory not provided or does not exist")
        raise HTTPException(status_code=400, detail="Invalid repository directory")

    try:
        flattened_code = ""
        count_code = ""
        for file_path in contract_files:
            full_path = os.path.join(project_dir, file_path)
            if not os.path.isfile(full_path):
                logger.error(f"Contract file '{file_path}' not found")
                raise HTTPException(
                    status_code=404, detail=f"Contract file '{file_path}' not found"
                )
            with open(full_path, "r", encoding="utf-8") as f:
                file_content = f.read()
                flattened_code += f"// File: {file_path}\n"
                flattened_code += file_content + "\n\n"
                count_code += file_content

        code_analysis = await count_lines_of_code(count_code)
        logger.info("Selected contracts flattened code successfully")
        return flattened_code, code_analysis

    except HTTPException:
        raise
    except Exception as e:
        logger.exception("Failed to flatten contracts")
        raise HTTPException(status_code=500, detail="Failed to flatten contracts") from e
