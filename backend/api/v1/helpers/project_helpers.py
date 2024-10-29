import os
import shutil
from pathlib import Path
from typing import List, Tuple

from api.v1.helpers.run_command import run_command
from common import logger
from config.solidity import (
    BROWNIE_CONFIGS,
    FORGE_BUILD_COMMAND,
    FOUNDRY_CONFIGS,
    HARDHAT_CONFIGS,
    SOLIDITY_EXTENSION,
)


def detect_project_type(repo_dir: str) -> Tuple[str, List[str]]:
    """
    Detects the project type (Foundry, Hardhat, or Brownie) and gathers contract folders.

    Args:
        repo_dir (str): The directory of the cloned repository.

    Returns:
        Tuple[str, List[str]]: A tuple containing the project type and a list of contract folder paths.
    """
    repo_path = Path(repo_dir)

    # Initialize project_type
    project_type = "unknown"

    # Start by detecting Foundry project
    foundry_config_found = False
    for config_name in FOUNDRY_CONFIGS:
        if (repo_path / config_name).exists():
            foundry_config_found = True
            logger.info(f"Foundry configuration detected: {config_name}")
            break
    if foundry_config_found:
        project_type = "foundry"
    else:
        # Check for Hardhat project
        hardhat_config_found = False
        for config_name in HARDHAT_CONFIGS:
            if (repo_path / config_name).exists():
                hardhat_config_found = True
                break
        if hardhat_config_found:
            project_type = "hardhat"
        else:
            # Check for Brownie project
            brownie_config_found = False
            for config_name in BROWNIE_CONFIGS:
                if (repo_path / config_name).exists():
                    brownie_config_found = True
                    logger.info(f"Brownie configuration detected: {config_name}")
                    break
            if brownie_config_found:
                project_type = "brownie"
            else:
                # Default to Foundry if no project type detected
                logger.warning("Project type not detected. Defaulting to Foundry.")
                project_type = "foundry"

    logger.info(f"Detected project type: {project_type}")
    return project_type


def get_project_structure(project_dir: str) -> str:
    """
    Generates a string representation of the project structure.

    Args:
        project_dir (str): The directory of the project.

    Returns:
        str: A string representing the project structure.
    """
    logger.info("Generating project structure...")
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
    return project_structure


async def clone_repository(github_url: str, tmpdirname: str, oauth_token: str = None) -> str:
    """
    Clones a GitHub repository into a specified temporary directory.

    This function uses the `git clone` command to clone a repository from GitHub into a temporary directory.
    If an OAuth token is provided, it is used for authentication to clone private repositories.

    Args:
        github_url (str): The URL of the GitHub repository to clone.
        tmpdirname (str): The path to the temporary directory where the repository will be cloned.
        oauth_token (str, optional): The OAuth token for private repositories. Defaults to None.

    Returns:
        str: The path to the cloned repository directory.

    Raises:
        ValueError: If the repository cloning fails.
    """
    logger.info("Cloning repositoy...")
    repo_name = str(github_url).split("/")[-1].replace(".git", "")
    repo_dir = os.path.join(tmpdirname, repo_name)

    git_clone_command = [
        "git",
        "clone",
        "--depth",
        "1",
        (
            github_url
            if oauth_token is None
            else str(github_url).replace("https://", f"https://{oauth_token}@")
        ),
        repo_dir,
    ]

    returncode, stdout, stderr = await run_command(git_clone_command, ".")
    if returncode != 0:
        raise ValueError(f"Failed to clone the repository: {stderr}")

    return repo_dir


def copy_solidity_files(repo_dir: str, dst_dir: str, project_type: str) -> None:
    """
    Copies Solidity contract files from the repository to the destination directory.

    Args:
        repo_dir (str): The source repository directory.
        dst_dir (str): The destination directory.
        project_type (str): The type of the project (e.g., "hardhat", "foundry").

    Raises:
        ValueError: If the expected source folder does not exist in the repository.
    """
    src_folder = "contracts" if project_type == "hardhat" else "src"
    src_dir = os.path.join(repo_dir, src_folder)

    if not os.path.exists(src_dir):
        # Attempt to check the alternative directory
        alternative_folder = "src" if project_type == "hardhat" else "contracts"
        alternative_dir = os.path.join(repo_dir, alternative_folder)
        if not os.path.exists(alternative_dir):
            raise ValueError(
                f"{src_folder} and {alternative_folder} directories not found in {repo_dir}"
            )
        src_dir = alternative_dir

    for root, _, files in os.walk(src_dir):
        for file in files:
            if file.endswith(SOLIDITY_EXTENSION):
                src_path = os.path.join(root, file)
                rel_path = os.path.relpath(src_path, src_dir)
                dst_path = os.path.join(dst_dir, rel_path)
                os.makedirs(os.path.dirname(dst_path), exist_ok=True)
                shutil.copy2(src_path, dst_path)


async def compile_project(temp_dir: str) -> None:
    returncode, stdout, stderr = await run_command(FORGE_BUILD_COMMAND, temp_dir)
    if returncode != 0:
        # logger.error(f"Forge compilation failed. Stdout: {stdout}, Stderr: {stderr}")
        raise ValueError("Forge compilation failed")
    logger.info("Project compiled successfully")
