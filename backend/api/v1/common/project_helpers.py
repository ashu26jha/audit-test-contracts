import os
import shutil
from pathlib import Path

from config.solidity_settings import FORGE_BUILD_COMMAND, SOLIDITY_EXTENSION
from core.utils.logger import logger
from core.utils.run_command import run_command


async def compile_project(temp_dir: str) -> None:
    """Compiles the project using Forge."""
    try:
        # First try normal compilation
        returncode, stdout, stderr = await run_command(FORGE_BUILD_COMMAND, temp_dir)

        if returncode == 0:
            logger.info("Project compiled successfully")
            return

        # If compilation fails, log the output and analyze the error
        logger.error(f"Forge compilation output:\nSTDOUT:\n{stdout}\nSTDERR:\n{stderr}")

        # Analyze the error
        if _is_only_external_dependency_error(stderr, temp_dir):
            logger.warning("Compilation failed only in external dependencies, continuing anyway")
            # Create out directory to indicate partial success
            out_dir = os.path.join(temp_dir, "out")
            os.makedirs(out_dir, exist_ok=True)
            return

        # If it's a project-specific error, raise an exception
        raise ValueError(f"Forge compilation failed: {stderr}")
    except Exception as e:
        logger.error(f"Compilation error in {temp_dir}: {str(e)}")
        raise


def _is_only_external_dependency_error(stderr: str, project_dir: str) -> bool:
    """Check if compilation errors are only in external dependencies."""
    error_lines = stderr.split("\n")
    for line in error_lines:
        if "Error" in line or "ParserError" in line:
            # Skip errors in lib/ directory or npm dependencies
            if "lib/" in line or "node_modules/" in line or "@" in line:
                continue
            # If we find an error in project files, return False
            if project_dir in line:
                return False
    return True


def get_project_structure(project_dir: str) -> str:
    """
    Generates a string representation of the project structure.
    """
    project_structure = ""
    repo_path = Path(project_dir)

    structure_lines = []
    for root, dirs, files in os.walk(project_dir):
        # Skip irrelevant directories
        dirs[:] = [
            d
            for d in dirs
            if d not in ["node_modules", "test", "lib", "scripts", "artifacts", "cache"]
        ]
        indent_level = len(Path(root).relative_to(repo_path).parts)
        indent = "    " * indent_level
        structure_lines.append(f"{indent}{Path(root).name}/")
        for file in files:
            structure_lines.append(f"{indent}    {file}")

    project_structure = "\n".join(structure_lines)

    logger.info("Project structure generated successfully")
    return project_structure


def copy_solidity_files(repo_dir: str, dst_dir: str, project_type: str) -> None:
    """
    Copies Solidity contract files from the repository to the destination directory.
    """
    # Try both src and contracts directories
    possible_src_dirs = ["src", "contracts"]
    if project_type == "hardhat":
        possible_src_dirs.reverse()  # Try contracts first for Hardhat

    src_dir = None
    for folder in possible_src_dirs:
        potential_dir = os.path.join(repo_dir, folder)
        if os.path.exists(potential_dir):
            src_dir = potential_dir
            break

    if not src_dir:
        raise ValueError(f"No valid source directory found in {repo_dir}")

    files_copied = 0
    for root, _, files in os.walk(src_dir):
        for file in files:
            if file.endswith(SOLIDITY_EXTENSION):
                src_path = os.path.join(root, file)
                rel_path = os.path.relpath(src_path, src_dir)
                dst_path = os.path.join(dst_dir, rel_path)
                os.makedirs(os.path.dirname(dst_path), exist_ok=True)
                shutil.copy2(src_path, dst_path)
                files_copied += 1

    if files_copied == 0:
        raise ValueError(f"No Solidity files found in {src_dir}")

    logger.info(f"Copied {files_copied} Solidity files from {src_dir} to {dst_dir}")
