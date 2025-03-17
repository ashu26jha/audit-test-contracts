import os
from typing import Dict, List

from api.v1.common.lines_of_code import count_lines_of_code
from core.models.scan import CodeAnalysisResult
from core.utils.errors import EnvironmentError, InitializationError
from core.utils.logger import logger


async def flatten_and_count_contracts(
    contract_files: List[str],
    project_dir: str,
) -> tuple[str, CodeAnalysisResult, Dict[str, str]]:
    """
    Flattens contract files and counts the lines of code from the provided repository directory.
    Used by audit_agent_service after repository is cloned.

    Args:
        contract_files (List[str]): List of contract files to flatten
        project_dir (str): Path to the cloned repository directory

    Returns:
        str: Concatenated contract code with file headers,
        CodeAnalysisResult: count of lines,
        Dict[str, str]: Mapping of file names to their content
    """
    if not project_dir or not os.path.exists(project_dir):
        logger.error("[Scan Init] Repository directory not provided or does not exist")
        raise EnvironmentError(
            message="Invalid repository directory", details={"project_dir": project_dir}
        )

    try:
        flattened_code = ""
        count_code = ""
        contract_contents = {}

        for file_path in contract_files:
            full_path = os.path.join(project_dir, file_path)
            if not os.path.isfile(full_path):
                logger.error(f"[Scan Init] Contract file '{file_path}' not found")
                raise EnvironmentError(
                    message=f"Contract file '{file_path}' not found",
                    details={"file_path": file_path},
                )
            with open(full_path, "r", encoding="utf-8") as f:
                file_content = f.read()
                flattened_code += f"// File: {file_path}\n"
                flattened_code += file_content + "\n\n"
                count_code += file_content
                contract_contents[os.path.basename(file_path)] = file_content

        code_analysis = await count_lines_of_code(count_code)
        logger.info("[Scan Init] Selected contracts flattened code successfully")
        return flattened_code, code_analysis, contract_contents

    except EnvironmentError:
        raise
    except Exception as e:
        logger.exception(f"[Scan Init] Failed to flatten contracts: {str(e)}")
        raise InitializationError(
            message="Failed to flatten contracts", details={"error": str(e)}
        ) from e
