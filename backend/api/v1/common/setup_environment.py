import os
import shutil
from pathlib import Path
from typing import List, Optional, Tuple

from pydantic import HttpUrl

from api.v1.common.forge_helpers import (
    generate_remappings_with_foundry,
    initialize_foundry_project,
    install_npm_deps,
    update_foundry_config,
)
from api.v1.common.project_detection import detect_project_config
from api.v1.common.project_helpers import compile_project, get_project_structure
from api.v1.github.helpers.clone_repo import clone_repo
from config.solidity_settings import FORGE_INSTALL_COMMAND
from core.schemas.scan_schema import SetupResult
from core.utils.logger import logger
from core.utils.run_command import run_command


async def setup_environment(
    github_url: HttpUrl,
    temp_dir: str,  # Directory where the repo is initially cloned
    oauth_token: str = None,
    branch: str = "main",
    contract_files: Optional[List[str]] = None,
) -> Optional[SetupResult]:
    """
    Sets up the environment for analysis. The temp_dir might:
    - Already contain a cloned repo (when called from audit_agent_service)
    - Need to be created (when called standalone from other services)
    """
    remappings = None
    project_dir = temp_dir
    cloned_repo_dir = temp_dir

    try:
        # Step 1: Ensure temp_dir exists and clone the repo if needed
        os.makedirs(temp_dir, exist_ok=True)
        if not os.listdir(temp_dir):
            github_url_str = str(github_url)
            cloned_repo_dir = await clone_repo(github_url_str, temp_dir, oauth_token, branch)
        else:
            cloned_repo_dir = temp_dir

        # Step 2: Detect project type and configuration
        project_config = await detect_project_config(cloned_repo_dir, contract_files)
        project_type = project_config.project_type
        project_dir = project_config.root_dir

        # Step 3: Set up the environment based on the project type
        if project_type == "hardhat":
            project_dir, remappings = await setup_hardhat_environment(
                project_type, project_dir, cloned_repo_dir
            )

        elif project_type == "foundry":
            remappings = await setup_foundry_environment(project_dir)
        else:
            raise NotImplementedError("This framework is not supported.")

        # Step 4: Compile the project
        try:
            await compile_project(project_dir)
        except Exception as e:
            logger.error(f"Project compilation failed: {str(e)}")
            return None

        # Step 5: Create the test directory and get project structure
        test_dir = Path(project_dir) / "test"
        test_dir.mkdir(parents=True, exist_ok=True)
        project_structure = get_project_structure(project_dir)

        return SetupResult(
            project_dir=project_dir,
            project_type=project_type,
            remappings=remappings,
            project_structure=project_structure,
        )

    except Exception as e:
        logger.error(f"Environment setup failed: {str(e)}")
        return None


async def cleanup_environment(temp_dir: str = None, project_dir: str = None):
    """Clean up temporary directories after scan completion"""
    try:
        if temp_dir and os.path.exists(temp_dir):
            shutil.rmtree(temp_dir)
            logger.info(f"Cleaned up temporary directory: {temp_dir}")

        if project_dir and os.path.exists(project_dir):
            if "foundry_project" in project_dir:
                # Clean up foundry project directory
                shutil.rmtree(project_dir)
                logger.info(f"Cleaned up foundry project directory: {project_dir}")
            else:
                # Clean up repository directory
                shutil.rmtree(project_dir)
                logger.info(f"Cleaned up repository directory: {project_dir}")

    except Exception as e:
        logger.error(f"Error during environment cleanup: {str(e)}")
        # Don't raise the error to avoid blocking task completion


async def setup_hardhat_environment(
    project_type: str, project_dir: str, cloned_repo_dir: str
) -> Tuple[str, List[str]]:
    # For Hardhat, create a new directory to initialize Foundry project
    foundry_dir = os.path.join(project_dir, "foundry_project")
    os.makedirs(foundry_dir, exist_ok=True)

    # Initialize Foundry project in the new directory
    await initialize_foundry_project(foundry_dir, project_dir, project_type)

    # Install NPM dependencies
    await install_npm_deps(foundry_dir, project_dir)

    # Update foundry.toml configuration and generate remappings
    update_foundry_config(foundry_dir)
    try:
        remappings = await generate_remappings_with_foundry(foundry_dir)
    except Exception as e:
        logger.warning(f"Failed to generate remappings with Foundry: {str(e)}")

    # Set project_dir to foundry directory
    project_dir = foundry_dir

    # Remove the original repo if it's not in the expected path
    if cloned_repo_dir != project_dir:
        # Check if project_dir is within cloned_repo_dir
        if os.path.commonpath([project_dir, cloned_repo_dir]) == cloned_repo_dir:
            # project_dir is within cloned_repo_dir, so we should not delete cloned_repo_dir
            logger.info("Not removing cloned_repo_dir because project_dir is within it.")
        else:
            # Safe to delete cloned_repo_dir
            try:
                shutil.rmtree(cloned_repo_dir)
                logger.info(f"Removed original Hardhat repository: {cloned_repo_dir}")
            except Exception as e:
                logger.warning(f"Failed to remove original repository: {str(e)}")

    logger.info("Hardhat project has been set up in Foundry.")
    return project_dir, remappings


async def setup_foundry_environment(project_dir: str) -> Optional[List[str]]:
    try:
        # Install Foundry dependencies
        await run_command(FORGE_INSTALL_COMMAND, project_dir)

        # Update foundry.toml configuration and generate remappings
        update_foundry_config(project_dir)
        try:
            remappings = await generate_remappings_with_foundry(project_dir)
        except Exception as e:
            logger.warning(f"Failed to generate remappings with Foundry: {str(e)}")
            return None

        logger.info("Foundry project dependencies installed.")
        return remappings
    except Exception as e:
        logger.error(f"Error running forge install: {str(e)}")
        return None
