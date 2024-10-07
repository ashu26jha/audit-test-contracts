import json
import os
import re
import shutil
from typing import Dict, List

import toml
from api.v1.utils.forge_helpers import run_command, write_remappings
from common import logger
from config.slither import PACKAGE_MAPPING


def parse_dependencies(repo_dir: str, project_type: str) -> Dict[str, str]:
    dependencies = {}
    if project_type == "hardhat":
        logger.info("Parsing dependencies for Hardhat project")

        package_json_path = os.path.join(repo_dir, "package.json")
        all_deps = {}

        if os.path.exists(package_json_path):
            with open(package_json_path, "r") as f:
                package_data = json.load(f)
            all_deps = {
                **package_data.get("dependencies", {}),
                **package_data.get("devDependencies", {}),
            }

            # Parse Solidity files for imports
            for root, _, files in os.walk(repo_dir):
                for file in files:
                    if file.endswith(".sol"):
                        with open(os.path.join(root, file), "r") as sol_file:
                            content = sol_file.read()
                            imports = re.findall(r'import\s+["\'](.+?)["\'];', content)

                            for imp in imports:
                                # Skip relative imports
                                if imp.startswith("."):
                                    continue

                                # Extract package name
                                parts = imp.split("/")
                                if len(parts) < 2:
                                    continue  # Not a package import

                                if parts[0].startswith("@"):
                                    package = f"{parts[0]}/{parts[1]}"
                                else:
                                    package = parts[0]

                                # Skip Hardhat-related packages
                                if "hardhat" in package.lower():
                                    continue

                                # Get the version from package.json dependencies
                                version = all_deps.get(package)

                                # If the package is not in package.json, try matching partial names
                                if not version:
                                    for dep_name in all_deps.keys():
                                        if dep_name.startswith(package):
                                            version = all_deps[dep_name]
                                            package = dep_name
                                            break

                                # If version is still not found, set it to 'latest'
                                if not version:
                                    version = "latest"

                                dependencies[package] = version

    elif project_type == "foundry":
        foundry_toml_path = os.path.join(repo_dir, "foundry.toml")
        if os.path.exists(foundry_toml_path):
            with open(foundry_toml_path, "r") as f:
                config = toml.load(f)
            deps = config.get("libs", {})
            dependencies.update(deps)

    return dependencies


async def install_dependencies(
    temp_dir: str, dependencies: Dict[str, str], project_type: str
) -> Dict[str, str]:
    lib_dir = os.path.join(temp_dir, "lib")
    custom_remappings = {}

    # Ensure 'lib' directory is empty
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
        # Normalize package name for comparison
        normalized_package = package.lower().replace("@", "").replace("/", "-")

        # Handle known packages
        repo = None
        for known_package, repo_url in PACKAGE_MAPPING.items():
            if known_package in normalized_package:
                repo = repo_url
                break

        if not repo:
            # Infer the GitHub repo from the package name
            repo = package.strip("@").replace("/", "/")

        # Clean up the version string
        version = version.strip()
        # Remove npm tags like 'npm:', 'github:'

        if ":" in version:
            version = version.split(":")[-1]

        # If the version contains '@', split and take the last part (the version number)
        if "@" in version:
            # Handles cases like 'npm:@openzeppelin/contracts@^4.7.3'
            version = version.split("@")[-1]

        # Remove any version specifiers like '^', '~', '>=', '<=', etc.
        version = re.sub(r"^[\^~<>=]+", "", version)

        # Ensure version is properly formatted (e.g., for OpenZeppelin contracts)
        if "openzeppelin-contracts" in normalized_package and not version.startswith("v"):
            version = f"v{version}"

        # Build install command
        install_target = f"{repo}@{version}"
        install_command = ["forge", "install", install_target, "--no-commit"]

        logger.info(f"Installing {install_target}")
        returncode, stdout, stderr = await run_command(install_command, temp_dir)
        if returncode != 0:
            logger.warning(f"Failed to install {install_target}: {stderr}")
            # Attempt to install without version tag as a fallback
            logger.info(f"Attempting to install {repo} without version.")
            install_command = ["forge", "install", repo, "--no-commit"]
            returncode, stdout, stderr = await run_command(install_command, temp_dir)
            if returncode != 0:
                logger.error(f"Failed to install {repo} without version: {stderr}")
                continue  # Move on to the next dependency

        # Adjust folder_name for OpenZeppelin packages
        if repo.lower() == "openzeppelin/openzeppelin-contracts":
            folder_name = "openzeppelin-contracts"
        elif repo.lower() == "openzeppelin/openzeppelin-contracts-upgradeable":
            folder_name = "openzeppelin-contracts-upgradeable"
        else:
            folder_name = repo.split("/")[-1]

        # Store the remapping and the actual folder name
        custom_remappings[package] = {
            "remapping": package,  # The import path as used in .sol files
            "folder_name": folder_name,  # Actual folder name in 'lib' directory
        }

    logger.info("Dependencies installed successfully")
    return custom_remappings


async def generate_and_write_remappings(
    temp_dir: str, custom_remappings: Dict[str, str]
) -> List[str]:
    remappings = []

    for package, data in custom_remappings.items():
        remapping = data["remapping"]  # The custom import path
        folder_name = data["folder_name"]  # The actual folder in 'lib'

        # For OpenZeppelin packages, adjust the remapping to include 'contracts/'
        if package.startswith("@openzeppelin/contracts") or package.startswith(
            "@openzeppelin/contracts-upgradeable"
        ):
            remappings.append(f"{remapping}/=lib/{folder_name}/contracts/")
        else:
            remappings.append(f"{remapping}/=lib/{folder_name}/")

    # Remove duplicates while preserving order
    remappings = list(dict.fromkeys(remappings))

    logger.info(f"Remappings generated: {remappings}")

    logger.info("Writing remappings...")
    await write_remappings(temp_dir, remappings)
    logger.info("Remappings written successfully")

    return remappings


def find_import_remappings(temp_dir: str) -> List[str]:
    remappings = []
    # remapping_pattern = r'import ["\'](.+?)["\'];'

    for root, _, files in os.walk(temp_dir):
        for file in files:
            if file.endswith(".sol"):
                with open(os.path.join(root, file), "r") as f:
                    content = f.read()
                    imports = re.findall(r'import ["\'](.+?)["\'];', content)

                    for imp in imports:
                        parts = imp.split("/")
                        if (
                            len(parts) > 1
                            and not imp.startswith("./")
                            and not imp.startswith("../")
                        ):
                            if parts[0].startswith("@"):
                                # Handle scoped packages like @openzeppelin
                                remappings.append(
                                    f"{parts[0]}/{parts[1]}/=lib/{parts[0].replace('@', '')}-{parts[1]}/"
                                )
                            else:
                                remappings.append(f"{parts[0]}/=lib/{parts[0]}/")
    return list(set(remappings))
