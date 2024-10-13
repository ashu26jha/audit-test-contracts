import asyncio
import os
import re
import shutil
import subprocess
from typing import Dict, List, Tuple

import toml

from common import logger
from config.slither import POSSIBLE_CONTRACT_FOLDERS, SOLIDITY_EXTENSION


def find_contract_folders(repo_dir: str) -> List[str]:
    """
    Identifies and returns a list of contract folders within the given repository directory.

    Args:
        repo_dir (str): The root directory of the repository.

    Returns:
        List[str]: A list of relative paths to contract folders.
    """
    contract_folders = []
    possible_folders = POSSIBLE_CONTRACT_FOLDERS.copy()

    for root, dirs, files in os.walk(repo_dir):
        for folder in possible_folders:
            if folder in dirs:
                contract_folders.append(os.path.relpath(os.path.join(root, folder), repo_dir))

        if any(file.endswith(SOLIDITY_EXTENSION) for file in files):
            contract_folders.append(os.path.relpath(root, repo_dir))

    return list(set(contract_folders))


def clean_unused_files(temp_dir: str) -> None:
    """
    Cleans up unused files in specified folders within the temporary directory.

    Args:
        temp_dir (str): The temporary directory path.
    """
    for folder in ["src", "script", "test"]:
        folder_path = os.path.join(temp_dir, folder)
        if os.path.exists(folder_path):
            for item in os.listdir(folder_path):
                item_path = os.path.join(folder_path, item)
                if os.path.isfile(item_path):
                    os.unlink(item_path)
                elif os.path.isdir(item_path):
                    shutil.rmtree(item_path)
    logger.info("Unused files cleaned up.")


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
        raise ValueError(f"{src_folder} directory not found in {repo_dir}")

    for root, _, files in os.walk(src_dir):
        for file in files:
            if file.endswith(SOLIDITY_EXTENSION):
                src_path = os.path.join(root, file)
                rel_path = os.path.relpath(src_path, src_dir)
                dst_path = os.path.join(dst_dir, rel_path)
                os.makedirs(os.path.dirname(dst_path), exist_ok=True)
                shutil.copy2(src_path, dst_path)


async def write_remappings(temp_dir: str, remappings: List[str]) -> None:
    """
    Writes remappings to the `remappings.txt` file in the temporary directory.

    Args:
        temp_dir (str): The temporary directory path.
        remappings (List[str]): A list of remapping strings.
    """
    remappings_path = os.path.join(temp_dir, "remappings.txt")
    with open(remappings_path, "w") as f:
        f.write("\n".join(remappings))


async def run_command(
    command: List[str], cwd: str, env: Dict[str, str] = None
) -> Tuple[int, str, str]:
    """
    Executes a command asynchronously and captures its output.

    Args:
        command (List[str]): The command and its arguments to execute.
        cwd (str): The working directory to run the command in.
        env (Dict[str, str], optional): Environment variables to set for the command.

    Returns:
        Tuple[int, str, str]: A tuple containing the return code, stdout, and stderr.
    """
    try:
        process = await asyncio.create_subprocess_exec(
            *command,
            cwd=cwd,
            env=env,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        stdout, stderr = await process.communicate()
        return process.returncode, stdout.decode(), stderr.decode()
    except Exception as e:
        logger.exception(
            f"Exception occurred while running command '{' '.join(command)}': {str(e)}"
        )
        raise


def run_command_sync(
    command: List[str], cwd: str, env: Dict[str, str] = None
) -> Tuple[int, str, str]:
    """
    Executes a command synchronously and captures its output.

    Args:
        command (List[str]): The command and its arguments to execute.
        cwd (str): The working directory to run the command in.
        env (Dict[str, str], optional): Environment variables to set for the command.

    Returns:
        Tuple[int, str, str]: A tuple containing the return code, stdout, and stderr.
    """
    try:
        process = subprocess.Popen(
            command,
            cwd=cwd,
            env=env,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
        stdout, stderr = process.communicate()
        return process.returncode, stdout.decode(), stderr.decode()
    except Exception as e:
        logger.exception(
            f"Exception occurred while running command '{' '.join(command)}' synchronously: {str(e)}"
        )
        raise


def preprocess_solidity_files(temp_dir: str) -> None:
    """
    Preprocesses Solidity files by replacing certain placeholders.

    Args:
        temp_dir (str): The temporary directory path.
    """
    logger.info("Preprocessing Solidity files to replace placeholders...")
    src_dir = os.path.join(temp_dir, "src")
    for root, _, files in os.walk(src_dir):
        for file in files:
            if file.endswith(".sol"):
                file_path = os.path.join(root, file)
                with open(file_path, "r") as f:
                    content = f.read()
                # Replace address variables assigned to empty strings
                content = re.sub(
                    r"(address\s+(?:public|private|internal|external)?\s*(?:constant\s+)?\s*\w+\s*=\s*)\"\";",
                    r"\1 address(0);",
                    content,
                )
                with open(file_path, "w") as f:
                    f.write(content)
    logger.info("Preprocessing completed")


def update_foundry_config(temp_dir: str) -> None:
    """
    Updates the `foundry.toml` configuration file with necessary settings.

    Args:
        temp_dir (str): The temporary directory path.

    Raises:
        FileNotFoundError: If the `foundry.toml` file is not found in the project directory.
    """
    logger.info("Updating foundry.toml configuration...")
    foundry_toml_path = os.path.join(temp_dir, "foundry.toml")
    if not os.path.exists(foundry_toml_path):
        raise FileNotFoundError("foundry.toml not found in the project directory.")

    with open(foundry_toml_path, "r") as f:
        config = toml.load(f)

    # Ensure the default profile exists
    config.setdefault("profile", {})
    config["profile"].setdefault("default", {})

    # Set 'solc' to 'auto' instead of 'solc_version'
    config["profile"]["default"]["auto_detect_solc"] = True

    # Set PROPTEST_MAX_SHRINK_ITERS
    # config["profile"]["default"]["fuzz"] = {
    #     "max_test_rejects": 65536,
    #     "max_shrink_iters": 1000,
    # }

    with open(foundry_toml_path, "w") as f:
        toml.dump(config, f)

    logger.info("foundry.toml updated successfully.")


def read_file(path: str) -> str:
    """
    Reads the content of a file.

    Args:
        path (str): The file path.

    Returns:
        str: The content of the file.
    """
    try:
        with open(path, "r") as file:
            content = file.read()
        return content
    except Exception as e:
        logger.exception(f"Error reading file {path}: {str(e)}")
        raise
