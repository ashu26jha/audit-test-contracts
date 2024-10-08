import os
from pathlib import Path
from typing import List, Tuple

from api.v1.helpers.forge_helpers import find_contract_folders, run_command
from common import logger
from config.slither import BROWNIE_CONFIGS, FOUNDRY_CONFIG, HARDHAT_CONFIGS


def detect_project_structure(repo_dir: str) -> Tuple[str, List[str], bool]:
    project_types = [
        ("foundry", [FOUNDRY_CONFIG]),
        ("hardhat", HARDHAT_CONFIGS),
        ("brownie", BROWNIE_CONFIGS),
    ]

    for project_type, config_files in project_types:
        for config in config_files:
            if os.path.exists(os.path.join(repo_dir, config)):
                contract_folders = find_contract_folders(repo_dir)
                # Filter out any 'lib/' folders
                contract_folders = [folder for folder in contract_folders if "lib/" not in folder]
                return project_type, contract_folders

    # If no specific config is found, assume it's a generic solidity project
    contract_folders = find_contract_folders(repo_dir)
    # Filter out any 'lib/' folders
    contract_folders = [folder for folder in contract_folders if "lib/" not in folder]
    return "generic", contract_folders


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

    logger.info("Repository cloned successfully")
    return repo_dir


async def compile_project(temp_dir: str) -> None:
    logger.info("Compiling project with Forge...")
    returncode, stdout, stderr = await run_command(["forge", "build"], temp_dir)
    if returncode != 0:
        logger.error(f"Forge compilation failed. Stdout: {stdout}, Stderr: {stderr}")
        raise ValueError(f"Forge compilation failed: {stderr}")
    logger.info("Project compiled successfully")


def get_project_structure(root_dir: str, contract_folders: List[str], level: int = 0) -> str:
    """
    Recursively generates a string representation of the project directory structure for specified contract folders.

    Args:
        root_dir (str): The root directory to start from.
        contract_folders (List[str]): List of contract folders to include in the structure.
        level (int): The current depth level for indentation.

    Returns:
        str: The formatted directory structure.
    """
    structure = ""
    prefix = "    " * level
    for folder in contract_folders:
        folder_path = Path(root_dir) / folder
        if folder_path.is_dir():
            structure += f"{prefix}{folder}/\n"
            for item in folder_path.iterdir():
                if item.is_dir():
                    structure += f"{prefix}    {item.name}/\n"
                    structure += get_project_structure(item, contract_folders, level + 2)
                else:
                    structure += f"{prefix}    {item.name}\n"

    return structure
