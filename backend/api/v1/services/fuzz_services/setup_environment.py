import os
import shutil
import tempfile
from pathlib import Path
from typing import Tuple

from api.v1.utils.dependencies import (
    generate_and_write_remappings,
    install_dependencies,
    parse_dependencies,
)
from api.v1.utils.forge_helpers import (
    copy_solidity_files,
    preprocess_solidity_files,
    run_command,
    update_foundry_config,
)
from api.v1.utils.project_helpers import (
    clone_repository,
    compile_project,
    detect_project_structure,
)
from api.v1.utils.solc_version import detect_and_install_solc_versions
from common import logger
from pydantic import HttpUrl


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
        solc_version = detect_and_install_solc_versions(repo_dir)

        print(repo_dir)
        if project_type == "brownie":
            raise NotImplementedError(f"{project_type} is currently not implemented")

        # TODO: Fix hardhat project setup
        if project_type == "hardhat":
            repo_name = os.path.basename(repo_dir)
            foundry_project_name = f"{repo_name}Foundry"
            foundry_project_dir = os.path.join(tmpdirname, foundry_project_name)
            os.makedirs(foundry_project_dir, exist_ok=True)
            logger.info(f"Created directory: {foundry_project_dir}")

            await run_command(
                ["forge", "init", "--template", "DanielBoye/foundry-template"],
                foundry_project_dir,
            )

            foundry_src_dir = os.path.join(foundry_project_dir, "src")
            copy_solidity_files(repo_dir, foundry_src_dir, project_type)

            preprocess_solidity_files(foundry_project_dir)

            # Remove Counter.sol from src directory
            counter_sol_path = os.path.join(foundry_project_dir, "src", "Counter.sol")
            if os.path.exists(counter_sol_path):
                os.remove(counter_sol_path)
                logger.info(f"Removed {counter_sol_path}")

            # Remove Counter.s.sol from script directory
            counter_s_sol_path = os.path.join(
                foundry_project_dir, "script", "Counter.s.sol"
            )
            if os.path.exists(counter_s_sol_path):
                os.remove(counter_s_sol_path)
                logger.info(f"Removed {counter_s_sol_path}")

            # Remove Counter.t.sol from test directory
            counter_t_sol_path = os.path.join(
                foundry_project_dir, "test", "Counter.t.sol"
            )
            if os.path.exists(counter_t_sol_path):
                os.remove(counter_t_sol_path)
                logger.info(f"Removed {counter_t_sol_path}")

            # Now use the project_helpers functions to set up the project
            dependencies = parse_dependencies(repo_dir, project_type)
            logger.info(f"DEPENDENCIES: {dependencies}")
            custom_remappings = await install_dependencies(
                foundry_project_dir, dependencies, project_type
            )
            await generate_and_write_remappings(foundry_project_dir, custom_remappings)
            update_foundry_config(foundry_project_dir, solc_version)
            await compile_project(foundry_project_dir, solc_version)

            repo_dir = foundry_project_dir
            logger.info("Hardhat set up correctly")

        # Run "forge build" as a sanity check at the end
        await compile_project(repo_dir)

        project_type, contract_folders = detect_project_structure(repo_dir)

        return repo_dir, contract_folders, project_type, project_path

    except Exception as e:
        logger.error(f"Error setting up environment: {str(e)}")
        if os.path.exists(project_dir):
            shutil.rmtree(project_dir)
        raise
