import os
import shutil
import tempfile
from typing import Any, Dict, List

from api.v1.schemas.static_analyzer_schema import SlitherOutput, StaticAnalyzerResponse
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
from api.v1.utils.slither_helpers import run_slither
from api.v1.utils.solc_version import detect_and_install_solc_versions
from common import logger


async def clone_and_analyze_repo(
    github_url: str, oauth_token: str = None, selected_contracts: List[str] = None
) -> StaticAnalyzerResponse:
    logger.info(f"Starting analysis for repository: {github_url}")
    with tempfile.TemporaryDirectory() as tmpdirname:
        # 1. Clone the repository
        repo_dir = await clone_repository(github_url, tmpdirname, oauth_token)

        # 2. Detect the project structure
        project_type, contract_folders = detect_project_structure(repo_dir)

        # 3. Setup the environment
        slither_output = await setup_environment(repo_dir, project_type, selected_contracts or [])
        return StaticAnalyzerResponse(
            message="Repository analyzed successfully.",
            status="Success",
            project_type=project_type,
            contract_folders=contract_folders,
            environment_setup="Analysis completed successfully",
            slither_output=SlitherOutput(**slither_output),
        )


async def setup_environment(
    repo_dir: str, project_type: str, selected_contracts: List[str]
) -> List[Dict[str, Any]]:
    logger.info(f"Setting up environment for {project_type} project in {repo_dir}")
    temp_dir = tempfile.mkdtemp()

    try:
        await initialize_foundry_project(temp_dir)

        src_dir = os.path.join(temp_dir, "src")
        os.makedirs(src_dir, exist_ok=True)
        copy_solidity_files(repo_dir, src_dir, project_type)

        # Preprocess Solidity files
        preprocess_solidity_files(temp_dir)

        dependencies = parse_dependencies(repo_dir, project_type)
        custom_remappings = await install_dependencies(temp_dir, dependencies, project_type)
        remappings = await generate_and_write_remappings(temp_dir, custom_remappings)

        # Detect and install all required Solidity versions
        detect_and_install_solc_versions(temp_dir)

        # Update foundry.toml to use 'auto' solc version
        update_foundry_config(temp_dir)

        await compile_project(temp_dir)
        slither_output = await run_slither(temp_dir, remappings, selected_contracts)
        return slither_output
    finally:
        shutil.rmtree(temp_dir)


async def initialize_foundry_project(temp_dir: str) -> None:
    logger.info("Initializing Foundry project...")
    commands = [
        ["git", "init"],
        ["forge", "init", "--force", "--no-commit"],
    ]
    for command in commands:
        returncode, stdout, stderr = await run_command(command, temp_dir)
        if returncode != 0:
            raise ValueError(f"Failed to initialize Foundry project: {stderr}")

    # Remove contents of the src, script, and test folders
    logger.info("Removing unused foundry contents...")
    for folder in ["src", "script", "test"]:
        folder_path = os.path.join(temp_dir, folder)
        if os.path.exists(folder_path):
            for item in os.listdir(folder_path):
                item_path = os.path.join(folder_path, item)
                if os.path.isfile(item_path):
                    os.unlink(item_path)
                elif os.path.isdir(item_path):
                    shutil.rmtree(item_path)

    logger.info("Foundry project initialized successfully")
