import os
from pathlib import Path

from api.v1.helpers.dependencies_helpers import (
    generate_and_write_remappings,
    install_dependencies,
    parse_dependencies,
)
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
from pydantic import HttpUrl


async def setup_environment(
    github_url: HttpUrl, oauth_token: str = None, temp_dir: str = None
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

    try:
        project_path = Path(temp_dir)
        github_url_str = str(github_url)
        repo_dir = await clone_repository(github_url_str, temp_dir, oauth_token)

        # Detect project structure
        project_type, contract_folders = detect_project_structure(repo_dir)
        logger.info(f"Project type: {project_type}")

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

            # Now use the project_helpers functions to set up the project
            dependencies = parse_dependencies(repo_dir, project_type)
            logger.info(f"DEPENDENCIES: {dependencies}")

            # Install dependencies and track remappings
            custom_remappings = await install_dependencies(
                temp_dir, dependencies, project_type
            )
            remappings = await generate_and_write_remappings(
                temp_dir, custom_remappings
            )

            # Detect and install all required Solidity versions
            solc_version = detect_and_install_solc_versions(repo_dir)

            # Update foundry.toml to use 'auto' solc version
            update_foundry_config(temp_dir)

            repo_dir = temp_dir
            logger.info("Hardhat set up correctly")

        # Run "forge build" as a sanity check at the end
        await compile_project(repo_dir)

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
