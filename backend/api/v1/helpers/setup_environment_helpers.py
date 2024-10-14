import os
import shutil
from pathlib import Path

from pydantic import HttpUrl

from api.v1.helpers.dependencies_helpers import generate_remappings_with_foundry
from api.v1.helpers.forge_helpers import (
    clean_unused_files,
    copy_solidity_files,
    preprocess_solidity_files,
    run_command,
    update_foundry_config,
)
from api.v1.helpers.project_helpers import (
    clone_repository,
    compile_project,
    detect_project_structure,
)
from api.v1.helpers.solc_helpers import detect_and_install_solc_versions
from api.v1.schemas.fuzzer_schema import SetupResult
from common import logger


async def setup_environment(
    github_url: HttpUrl, temp_dir: str, oauth_token: str = None
) -> SetupResult:
    """
    Sets up the environment by creating a temporary directory, cloning the repository,
    initializing a Foundry project, and adding the contract to the src directory.

    Args:
        github_url (HttpUrl): The GitHub repository URL.
        oauth_token (str): The OAuth token for private repositories.

    Returns:
        SetupResult: An instance containing project directory, contract folders, project type, project path, and solc version.
    """

    contract_folders = None
    solc_version = None
    remappings = None

    try:
        project_path = Path(temp_dir)
        github_url_str = str(github_url)
        repo_dir = await clone_repository(github_url_str, temp_dir, oauth_token)

        # Detect project structure
        project_type, contract_folders = detect_project_structure(repo_dir)

        if project_type == "brownie":
            raise NotImplementedError(f"{project_type} is currently not implemented")

        if project_type == "hardhat":
            logger.info("Initializing Foundry project...")
            commands = [
                ["git", "init"],
                ["forge", "init", "--force", "--no-commit"],
            ]
            for command in commands:
                returncode, stdout, stderr = await run_command(command, temp_dir)
                if returncode != 0:
                    raise ValueError(f"Failed to initialize Foundry project: {stderr}")

            clean_unused_files(temp_dir)

            foundry_src_dir = os.path.join(temp_dir, "src")
            copy_solidity_files(repo_dir, foundry_src_dir, project_type)
            preprocess_solidity_files(temp_dir)

            # Copy package.json and package-lock.json from Hardhat project to Foundry project
            for file_name in ["package.json", "package-lock.json"]:
                src_file = os.path.join(repo_dir, file_name)
                dst_file = os.path.join(temp_dir, file_name)
                if os.path.exists(src_file):
                    shutil.copy2(src_file, dst_file)
                    logger.info(f"Copied {file_name} to Foundry project.")

            # Install NPM dependencies in the Foundry project
            try:
                logger.info("Installing NPM dependencies...")
                returncode, stdout, stderr = await run_command(["npm", "install"], temp_dir)
                if returncode != 0:
                    if 'ERESOLVE' in stderr:
                        logger.warning("NPM install failed due to dependency conflict. Retrying with --legacy-peer-deps.")
                        returncode, stdout, stderr = await run_command(
                            ["npm", "install", "--legacy-peer-deps"], temp_dir
                        )
                        if returncode != 0:
                            logger.error(f"NPM install failed: {stderr}")
                            raise ValueError(f"NPM install failed: {stderr}")
                    else:
                        logger.error(f"NPM install failed: {stderr}")
                        raise ValueError(f"NPM install failed: {stderr}")
                else:
                    logger.info("NPM dependencies installed successfully.")
            except Exception as e:
                logger.error(f"Error installing NPM dependencies: {str(e)}")
                raise

            # Update foundry.toml to use 'auto' solc version and include 'node_modules' in libs
            update_foundry_config(temp_dir)

            # Generate remappings using Foundry
            try:
                remappings = await generate_remappings_with_foundry(temp_dir)
                logger.info("Remappings generated successfully using Foundry")
            except Exception as e:
                logger.warning(f"Failed to generate remappings with Foundry: {str(e)}")
                # Optionally, handle fallback or raise an error

            # Detect and install all required Solidity versions
            solc_version = detect_and_install_solc_versions(temp_dir)

            repo_dir = temp_dir
            logger.info("Hardhat set up correctly")

        elif project_type == "foundry":
            # Run Forge install
            project_path = repo_dir
            await run_command(["forge", "install"], temp_dir)
            logger.info("Foundry set up correctly")

            # Run "forge build" as a sanity check at the end

        # Compile the project
        try:
            await compile_project(repo_dir)
        except Exception as e:
            logger.error(f"Compilation failed with error: {str(e)}")
            raise

        return SetupResult(
            project_dir=repo_dir,
            contract_folders=contract_folders,
            project_type=project_type,
            project_path=str(project_path),
            solc_version=solc_version,
            remappings=remappings,
        )

    except Exception as e:
        logger.error(f"Error setting up environment: {str(e)}")
        raise
