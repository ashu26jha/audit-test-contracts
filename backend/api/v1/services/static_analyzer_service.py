import os
import shutil
import subprocess
import tempfile
from typing import Any, Dict, List, Tuple

from api.v1.schemas.static_analyzer_schema import SlitherOutput, StaticAnalyzerResponse
from api.v1.utils.forge_helpers import (
    preprocess_solidity_files,  # Import the new function
)
from api.v1.utils.forge_helpers import (
    copy_solidity_files,
    run_command,
    update_foundry_config,
    write_remappings,
)
from api.v1.utils.project_helpers import (
    detect_project_structure,
    find_import_remappings,
    find_solidity_version,
    parse_dependencies,
)
from api.v1.utils.slither_helpers import run_slither
from common import logger


async def clone_and_analyze_repo(
    github_url: str, oauth_token: str = None
) -> StaticAnalyzerResponse:
    logger.info(f"Starting analysis for repository: {github_url}")
    with tempfile.TemporaryDirectory() as tmpdirname:
        repo_dir = await clone_repository(github_url, tmpdirname, oauth_token)
        project_type, contract_folders = detect_project_structure(repo_dir)
        slither_output = await setup_environment(repo_dir, project_type)
        return StaticAnalyzerResponse(
            message="Repository analyzed successfully.",
            status="Success",
            project_type=project_type,
            contract_folders=contract_folders,
            environment_setup="Analysis completed successfully",
            slither_output=SlitherOutput(**slither_output),
        )


async def clone_repository(github_url: str, tmpdirname: str, oauth_token: str = None) -> str:
    logger.info("Cloning repository...")
    repo_name = str(github_url).split("/")[-1]
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


async def setup_environment(repo_dir: str, project_type: str) -> List[Dict[str, Any]]:
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
        await install_dependencies(temp_dir, dependencies, project_type)
        remappings = await generate_and_write_remappings(temp_dir)

        # Detect Solidity version and install it
        solc_version = detect_and_install_solc_version(temp_dir)

        # Update foundry.toml with the correct Solidity version
        update_foundry_config(temp_dir, solc_version)

        await compile_project(temp_dir, solc_version)
        slither_output = await run_slither(temp_dir, remappings, solc_version)

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
