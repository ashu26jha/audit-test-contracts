import os
import shutil
from pathlib import Path

from fastapi import HTTPException
from pydantic import HttpUrl

from api.v1.helpers.forge_helpers import (
    generate_remappings_with_foundry,
    initialize_foundry_project,
    install_npm_deps,
    update_foundry_config,
)
from api.v1.helpers.project_helpers import (
    compile_project,
    detect_project_type,
    get_project_structure,
)
from api.v1.helpers.run_command import run_command
from api.v1.schemas.fuzzer_schema import SetupResult
from common import logger
from common.clone_repo import clone_repo
from config.solidity import FORGE_INSTALL_COMMAND


async def setup_environment(
    github_url: HttpUrl,
    temp_dir: str,
    oauth_token: str = None,
    branch: str = "main",
) -> SetupResult:
    """
    Sets up the environment for analysis. The temp_dir might:
    - Already contain a cloned repo (when called from audit_agent_service)
    - Need to be created (when called standalone from other services)
    """
    remappings = None
    project_dir = temp_dir

    try:
        # Ensure temp_dir exists
        os.makedirs(temp_dir, exist_ok=True)

        # Check if temp_dir is empty (needs cloning)
        if not os.listdir(temp_dir):
            github_url_str = str(github_url)
            temp_dir = await clone_repo(github_url_str, temp_dir, oauth_token, branch)

        # Step 1: Detect project type
        project_type = detect_project_type(temp_dir)

        # Step 2: Set up the environment based on the project type
        if project_type == "brownie":
            raise NotImplementedError(f"{project_type} is currently not implemented")

        if project_type == "hardhat":
            # For Hardhat, create a new directory to initialize Foundry project
            project_dir = os.path.join(os.path.dirname(temp_dir), "foundry_project")
            os.makedirs(project_dir, exist_ok=True)

            # Initialize Foundry project in the new directory
            await initialize_foundry_project(project_dir, temp_dir, project_type)

            # Install NPM dependencies
            await install_npm_deps(project_dir, temp_dir)

            # Update foundry.toml configuration
            update_foundry_config(project_dir)

            # Generate remappings using Foundry
            try:
                remappings = await generate_remappings_with_foundry(project_dir)
            except Exception as e:
                logger.warning(f"Failed to generate remappings with Foundry: {str(e)}")

            # Remove the original repo to prevent confusion & conflicts
            try:
                shutil.rmtree(temp_dir)
                logger.info(f"Removed original Hardhat repository: {temp_dir}")
            except Exception as e:
                logger.exception(f"Failed to remove original repository: {str(e)}")

            logger.info("Hardhat project has been set up in Foundry.")

        elif project_type == "foundry":
            try:
                await run_command(FORGE_INSTALL_COMMAND, project_dir)
                logger.info("Foundry project dependencies installed.")
            except Exception as e:
                logger.exception(f"Error running forge install: {str(e)}")
                raise

        # Step 3: Compile the project
        try:
            await compile_project(project_dir)
        except Exception as e:
            logger.exception(f"Project compilation failed: {str(e)}")
            raise HTTPException(status_code=500, detail="Failed to compile project")

        # Create the test directory if it doesn't exist
        test_dir = Path(project_dir) / "test"
        test_dir.mkdir(parents=True, exist_ok=True)

        # Step 4: Get the project structure
        project_structure = get_project_structure(project_dir)

        return SetupResult(
            project_dir=project_dir,
            project_type=project_type,
            remappings=remappings,
            project_structure=project_structure,
        )

    except ValueError:
        logger.exception("Invalid project configuration")
        raise HTTPException(status_code=400, detail="Invalid project configuration")
    except Exception:
        logger.exception("Environment setup failed")
        raise HTTPException(status_code=500, detail="Failed to set up environment")
