import shutil
from pathlib import Path

from pydantic import HttpUrl

from api.v1.helpers.forge_helpers import (
    generate_remappings_with_foundry,
    initialize_foundry_project,
    install_npm_deps,
    update_foundry_config,
)
from api.v1.helpers.project_helpers import (
    clone_repository,
    compile_project,
    detect_project_type,
    get_project_structure,
)
from api.v1.helpers.run_command import run_command
from api.v1.schemas.fuzzer_schema import SetupResult
from common import logger
from config.solidity import FORGE_INSTALL_COMMAND


async def setup_environment(
    github_url: HttpUrl, temp_dir: str, oauth_token: str = None
) -> SetupResult:
    """
    Sets up the environment by cloning the repository, initializing a Foundry project,
    and preparing it for fuzz testing.

    Args:
        github_url (HttpUrl): The GitHub repository URL.
        oauth_token (str): The OAuth token for private repositories.

    Returns:
        SetupResult: An instance containing project directory, contract folders, project type, project path, and project structure.
    """

    remappings = None

    try:
        github_url_str = str(github_url)
        repo_dir = await clone_repository(github_url_str, temp_dir, oauth_token)

        # Step 1: Detect project type
        project_type = detect_project_type(repo_dir)

        # Step 2: Set up the environment based on the project type
        if project_type == "brownie":
            raise NotImplementedError(f"{project_type} is currently not implemented")

        if project_type == "hardhat":
            # Initialize a new Foundry project in temp_dir
            await initialize_foundry_project(temp_dir, repo_dir, project_type)

            # Install NPM dependencies in the Foundry project
            await install_npm_deps(temp_dir, repo_dir)

            # Update foundry.toml to use 'auto' solc version and include 'node_modules' in libs
            update_foundry_config(temp_dir)

            # Generate remappings using Foundry
            try:
                remappings = await generate_remappings_with_foundry(temp_dir)
                logger.info("Remappings generated successfully using Foundry")
            except Exception as e:
                logger.warning(f"Failed to generate remappings with Foundry: {str(e)}")
                # Optionally, handle fallback or raise an error

            # Remove the initial cloned repository to avoid compilation issues and confusion
            if repo_dir != temp_dir:
                try:
                    logger.info(f"Removing initial cloned repository at {repo_dir}")
                    shutil.rmtree(repo_dir)
                    logger.info("Initial cloned repository removed successfully.")
                except Exception as e:
                    logger.error(f"Failed to remove initial cloned repository: {str(e)}")

            # Update repo_dir to temp_dir since the project is now set up in temp_dir
            repo_dir = temp_dir
            logger.info("Hardhat project has been set up in Foundry.")

        elif project_type == "foundry":
            try:
                await run_command(FORGE_INSTALL_COMMAND, repo_dir)
                logger.info("Foundry project dependencies installed.")
            except Exception as e:
                logger.error(f"Error running forge install: {str(e)}")
                raise

        else:
            logger.error(f"Unsupported project type: {project_type}")
            raise ValueError(f"Unsupported project type: {project_type}")

        # Step 3: Compile the project
        try:
            await compile_project(repo_dir)
        except Exception as e:
            logger.error(f"Compilation failed with error: {str(e)}")
            raise

        # Create the test directory if it doesn't exist
        test_dir = Path(temp_dir) / "test"
        test_dir.mkdir(parents=True, exist_ok=True)

        # Step 4: After setting up the environment, get the project structure
        project_structure = get_project_structure(repo_dir)

        return SetupResult(
            project_dir=repo_dir,
            project_type=project_type,
            remappings=remappings,
            project_structure=project_structure,
        )

    except Exception as e:
        logger.error(f"Error setting up environment: {str(e)}")
        raise
