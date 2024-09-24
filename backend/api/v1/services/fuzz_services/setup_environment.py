import asyncio
import os
import tempfile
import shutil
from typing import Tuple
from pathlib import Path
from api.v1.utils.forge_helpers import (
    copy_solidity_files,
    run_command,
    update_foundry_config,
)
from api.v1.utils.project_helpers import (
    detect_project_structure,
    parse_dependencies,
    install_dependencies,
    generate_and_write_remappings,
    detect_and_install_solc_version,
    compile_project,
    clone_repository,
)
from pydantic import HttpUrl
from common import logger

async def setup_environment(github_url: HttpUrl, oauth_token: str) -> Tuple[str, str]:
    """
    Sets up the environment by creating a temporary directory, cloning the repository,
    initializing a Foundry project, and adding the contract to the src directory.

    Args:
        github_url (HttpUrl): The GitHub repository URL.
        oauth_token (str): The OAuth token for private repositories.

    Returns:
        Tuple[str, str]: The project directory and contract name.
    """

    tmpdirname = tempfile.mkdtemp(prefix="fuzz_project_")


    try:
        project_dir = tmpdirname
        project_path = Path(project_dir)

        github_url_str = str(github_url)

        repo_dir = await clone_repository(github_url_str, project_dir, oauth_token)
        # NOTE: Debugging: Print all files in the project directory, ignoring .git directory
        # for root, dirs, files in os.walk(project_dir):
        #     # Skip .git directory
        #     if '.git' in dirs:
        #         dirs.remove('.git')
        #     for file in files:
        #         logger.info(os.path.join(root, file))

        project_type, contract_folders = detect_project_structure(repo_dir)

        # TODO: Fix hardhat project setup
        if project_type == "hardhat" or project_type == "brownie":
            # Psuedocode

            # Set up a viritual environment
            # Initialize a foundry project
            # Copy the solidity files into the foundry project
            # Detect the dependencies
            # Install the dependencies
            # Generate the remappings
            # Detect the solidity version
            # Update the foundry.toml file
            # Run the forge build command

            # dependencies = parse_dependencies(repo_dir, project_type)
            # await install_dependencies(project_dir, dependencies, project_type)
            # remappings = await generate_and_write_remappings(project_dir)
            # solc_version = detect_and_install_solc_version(project_dir)
            # update_foundry_config(project_dir, solc_version)
            # await compile_project(project_dir, solc_version)
            # print(f"Dependencies: {dependencies}")
            raise NotImplementedError(f"{project_type} project setup not implemented")

        # Run "forge build" as a sanity check
        returncode, stdout, stderr = await run_command(["forge", "build"], repo_dir)
        if returncode != 0:
            raise ValueError(f"Sanity check failed: {stderr}")
        logger.info("Sanity check passed: Project compiled successfully.")

        return repo_dir, contract_folders, project_type, project_path

    except Exception as e:
        logger.error(f"Error setting up environment: {str(e)}")
        if os.path.exists(project_dir):
            shutil.rmtree(project_dir)
        raise
