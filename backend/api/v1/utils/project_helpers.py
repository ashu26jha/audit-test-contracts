import json
import os
import re
import shutil
import subprocess
from pathlib import Path
from typing import Dict, List, Optional, Tuple

import toml
from api.v1.utils.forge_helpers import (
    find_contract_folders,
    run_command,
    write_remappings,
)
from common import logger

FOUNDRY_CONFIG = "foundry.toml"
HARDHAT_CONFIGS = [
    "hardhat.config.js",
    "hardhat.config.ts",
    "hardhat.config.cjs",
    "hardhat.config.mjs",
]
BROWNIE_CONFIGS = ["brownie-config.yaml", "brownie-config.json"]


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
                contract_folders = [folder for folder in contract_folders if 'lib/' not in folder]
                return project_type, contract_folders

    # If no specific config is found, assume it's a generic solidity project
    contract_folders = find_contract_folders(repo_dir)
    # Filter out any 'lib/' folders
    contract_folders = [folder for folder in contract_folders if 'lib/' not in folder]
    return "generic", contract_folders


def parse_dependencies(repo_dir: str, project_type: str) -> Dict[str, str]:
    dependencies = {}
    if project_type == "hardhat":
        package_json_path = os.path.join(repo_dir, "package.json")
        if os.path.exists(package_json_path):
            with open(package_json_path, "r") as f:
                package_data = json.load(f)
            all_deps = {
                **package_data.get("dependencies", {}),
                **package_data.get("devDependencies", {}),
            }

            # Parse Solidity files for imports
            for root, _, files in os.walk(repo_dir):
                for file in files:
                    if file.endswith(".sol"):
                        with open(os.path.join(root, file), "r") as sol_file:
                            content = sol_file.read()
                            imports = re.findall(r'import ["\'](.+?)["\'];', content)
                            for imp in imports:
                                # Extract package name
                                parts = imp.split("/")
                                if parts[0].startswith("@"):
                                    package = f"{parts[0]}/{parts[1]}"
                                else:
                                    package = parts[0]
                                if package in all_deps:
                                    dependencies[package] = all_deps[package]
                                else:
                                    dependencies[package] = "latest"
    elif project_type == "foundry":
        foundry_toml_path = os.path.join(repo_dir, "foundry.toml")
        if os.path.exists(foundry_toml_path):
            with open(foundry_toml_path, "r") as f:
                config = toml.load(f)
            deps = config.get("libs", {})
            for dep in deps:
                dependencies[dep] = deps[dep]

    return dependencies


def find_import_remappings(temp_dir: str) -> List[str]:
    remappings = []
    for root, _, files in os.walk(temp_dir):
        for file in files:
            if file.endswith(".sol"):
                with open(os.path.join(root, file), "r") as f:
                    content = f.read()
                    imports = re.findall(r'import ["\'](.+?)["\'];', content)
                    for imp in imports:
                        parts = imp.split("/")
                        if (
                            len(parts) > 1
                            and not imp.startswith("./")
                            and not imp.startswith("../")
                        ):
                            if parts[0].startswith("@"):
                                # Handle scoped packages like @openzeppelin
                                remappings.append(
                                    f"{parts[0]}/{parts[1]}/=lib/{parts[0].replace('@', '')}-{parts[1]}/"
                                )
                            else:
                                remappings.append(f"{parts[0]}/=lib/{parts[0]}/")
    return list(set(remappings))


def parse_solidity_version(file_path: str) -> Optional[str]:
    with open(file_path, "r") as file:
        content = file.read()
        pragma_pattern = r"pragma solidity\s*(\^|>=|<=|>|<)?\s*(\d+\.\d+\.\d+)"
        match = re.search(pragma_pattern, content)
        if match:
            version = match.group(2)
            return version
    return None


def find_solidity_version(temp_dir: str) -> str:
    logger.info(f"Searching for Solidity version in {temp_dir}")
    for root, _, files in os.walk(temp_dir):
        for file in files:
            if file.endswith(".sol"):
                file_path = os.path.join(root, file)
                logger.info(f"Checking file: {file_path}")
                version = parse_solidity_version(file_path)
                if version:
                    logger.info(f"Found Solidity version: {version}")
                    return version
                else:
                    logger.warning(f"No Solidity version found in {file_path}")
    logger.error("No Solidity version found in any file")
    return "0.8.27"  # Use the same default version as in detect_and_install_solc_version


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


def run_command_sync(
    command: List[str], cwd: str, env: Dict[str, str] = None
) -> Tuple[int, str, str]:
    process = subprocess.Popen(
        command,
        cwd=cwd,
        env=env,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    stdout, stderr = process.communicate()
    return process.returncode, stdout.decode(), stderr.decode()


async def install_dependencies(
    temp_dir: str, dependencies: Dict[str, str], project_type: str
) -> None:
    lib_dir = os.path.join(temp_dir, "lib")

    # Check if lib directory exists and is not empty
    if os.path.exists(lib_dir) and os.listdir(lib_dir):
        logger.warning("lib directory is not empty. Removing existing contents.")
        shutil.rmtree(lib_dir)
        os.makedirs(lib_dir)

    # Always install forge-std
    logger.info("Installing forge-std")
    returncode, stdout, stderr = await run_command(
        ["forge", "install", "foundry-rs/forge-std", "--no-commit"], temp_dir
    )
    if returncode != 0:
        logger.error(f"Failed to install forge-std: {stderr}")
        raise ValueError(f"Failed to install forge-std: {stderr}")

    # Install all dependencies
    for package, version in dependencies.items():
        # Clean up version string and prefix with 'v'
        version = version.strip("^~")
        if not version.startswith("v"):
            version = f"v{version}"

        if package == "@openzeppelin/contracts":
            repo = f"OpenZeppelin/openzeppelin-contracts@{version}"
        elif package == "@chainlink/contracts":
            repo = f"smartcontractkit/chainlink@{version}"
        elif package == "solady":
            repo = f"Vectorized/solady@{version}"
        elif package == "solmate":
            repo = f"rari-capital/solmate@{version}"
        else:
            logger.warning(f"Unknown package {package}, skipping.")
            continue  # Skip unknown packages or implement mapping

        logger.info(f"Installing {repo}")
        returncode, stdout, stderr = await run_command(
            ["forge", "install", repo, "--no-commit"], temp_dir
        )
        if returncode != 0:
            logger.warning(f"Failed to install {repo}: {stderr}")
            # Attempt to install without version tag as a fallback
            repo_without_version = repo.split("@")[0]
            logger.info(f"Attempting to install {repo_without_version} without version.")
            returncode, stdout, stderr = await run_command(
                ["forge", "install", repo_without_version, "--no-commit"], temp_dir
            )
            if returncode != 0:
                logger.error(f"Failed to install {repo_without_version}: {stderr}")
                raise ValueError(f"Failed to install {repo_without_version}: {stderr}")

    logger.info("Dependencies installed successfully")


async def generate_and_write_remappings(temp_dir: str) -> List[str]:
    logger.info("Generating remappings...")
    remappings = []
    lib_folder = os.path.join(temp_dir, "lib")
    if os.path.exists(lib_folder):
        for folder in os.listdir(lib_folder):
            folder_path = os.path.join(lib_folder, folder)
            if os.path.isdir(folder_path):
                if folder.startswith("openzeppelin-contracts"):
                    # Correct mapping for OpenZeppelin contracts
                    remappings.append(f"@openzeppelin/contracts/=lib/{folder}/contracts/")
                elif folder.startswith("chainlink"):
                    remappings.append(f"@chainlink/contracts/=lib/{folder}/contracts/src/v0.8/")
                elif folder == "solady":
                    remappings.append("solady/=lib/solady/src/")
                elif folder == "solmate":
                    remappings.append("solmate/=lib/solmate/src/")
                elif folder == "forge-std":
                    remappings.append("forge-std/=lib/forge-std/src/")
                else:
                    remappings.append(f"{folder}/=lib/{folder}/")

    # Add remappings from import statements
    import_remappings = find_import_remappings(temp_dir)
    remappings.extend(import_remappings)

    # Remove duplicates while preserving order
    remappings = list(dict.fromkeys(remappings))

    logger.info(f"Remappings generated: {remappings}")

    logger.info("Writing remappings...")
    await write_remappings(temp_dir, remappings)
    logger.info("Remappings written successfully")

    return remappings


def detect_and_install_solc_version(temp_dir: str) -> str:
    solc_version = find_solidity_version(temp_dir)
    if not solc_version:
        logger.warning("No Solidity version detected. Using default version 0.8.27")
        solc_version = "0.8.27"
    logger.info(f"Using Solc version: {solc_version}")

    install_solc_version(solc_version)

    return solc_version


def install_solc_version(version: str) -> None:
    logger.info(f"Installing Solc version {version}...")
    returncode, stdout, stderr = run_command_sync(["solc-select", "install", version], ".")
    if returncode != 0:
        raise ValueError(f"Failed to install solc version {version}: {stderr}")

    # Set the installed version as the active version
    returncode, stdout, stderr = run_command_sync(["solc-select", "use", version], ".")
    if returncode != 0:
        raise ValueError(f"Failed to set solc version {version}: {stderr}")
    logger.info(f"Solc version {version} installed and set successfully")


async def compile_project(temp_dir: str, solc_version: str) -> None:
    logger.info("Compiling project with Forge...")
    returncode, stdout, stderr = await run_command(
        [
            "forge",
            "build",
            "--use",
            f"solc:{solc_version}",
        ],
        temp_dir,
    )
    if returncode != 0:
        logger.error(f"Forge compilation failed. Stdout: {stdout}, Stderr: {stderr}")
        raise ValueError(f"Forge compilation failed: {stderr}")
    logger.info("Forge compilation successful")


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
