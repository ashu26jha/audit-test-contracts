import json
import os
import re
from typing import Dict, List, Set

from api.v1.helpers.forge_helpers import run_command, write_remappings
from common import logger
from config.slither import PACKAGE_MAPPING


def parse_dependencies(repo_dir: str, project_type: str) -> Dict[str, Dict[str, str]]:
    """
    Parses package.json to determine the required dependencies and their versions.

    Args:
        repo_dir (str): The repository directory.
        project_type (str): The project type (e.g., "hardhat").

    Returns:
        Dict[str, Dict[str, str]]: A dictionary with package names as keys and
                                    'version' as the value.
    """
    dependencies = {}
    if project_type == "hardhat":
        logger.info("Parsing dependencies for Hardhat project")

        # Read package.json to get all dependencies
        package_json_path = os.path.join(repo_dir, "package.json")
        if os.path.exists(package_json_path):
            with open(package_json_path, "r") as f:
                package_data = json.load(f)
            all_deps = {
                **package_data.get("dependencies", {}),
                **package_data.get("devDependencies", {}),
            }
        else:
            all_deps = {}

        # Exclude packages containing 'hardhat'
        dependencies_to_install = {
            pkg: ver for pkg, ver in all_deps.items() if "hardhat" not in pkg.lower()
        }

        # Filter dependencies to include only those present in PACKAGE_MAPPING
        for package_name, version in dependencies_to_install.items():
            if package_name in PACKAGE_MAPPING:
                dependencies[package_name] = {
                    "version": version,
                    "import_path": PACKAGE_MAPPING[package_name]["import_path"],
                }

    return dependencies


def find_import_paths(repo_dir: str) -> Set[str]:
    """
    Scans Solidity files to find all external import paths.

    Args:
        repo_dir (str): The repository directory.

    Returns:
        Set[str]: A set of external import paths.
    """
    import_paths = set()
    for root, _, files in os.walk(repo_dir):
        for file in files:
            if file.endswith(".sol"):
                with open(os.path.join(root, file), "r", encoding="utf-8") as f:
                    content = f.read()
                    imports = re.findall(r'import\s+["\']([^"\']+)["\'];', content)
                    for imp in imports:
                        if not imp.startswith("."):
                            # Collect the full import path
                            import_paths.add(imp)
    return import_paths


async def install_dependencies(
    temp_dir: str, dependencies: Dict[str, Dict[str, str]], project_type: str
) -> Dict[str, Dict[str, str]]:
    custom_remappings = {}

    # Ensure 'lib' directory exists
    lib_dir = os.path.join(temp_dir, "lib")
    os.makedirs(lib_dir, exist_ok=True)

    # Always install forge-std
    logger.info("Installing forge-std")
    returncode, stdout, stderr = await run_command(
        ["forge", "install", "foundry-rs/forge-std", "--no-commit"], temp_dir
    )
    if returncode != 0:
        logger.error(f"Failed to install forge-std: {stderr}")
        raise ValueError(f"Failed to install forge-std: {stderr}")

    for package_name, info in dependencies.items():
        version = info.get("version")
        import_path = info.get("import_path")

        # Get GitHub repo and lib folder name from PACKAGE_MAPPING
        mapping = PACKAGE_MAPPING.get(package_name)
        if not mapping:
            logger.warning(f"No mapping found for package '{package_name}'. Skipping")
            continue
        repo = mapping["github"]
        lib_folder = mapping.get("lib_folder", repo.split("/")[-1])

        # Clean up version string
        if version:
            version = version.strip()
            if version.startswith(("npm:", "github:")):
                version = version.split(":", 1)[-1]
            if "@" in version:
                version = version.split("@", 1)[-1]
            version = re.sub(r"^[\^~<>=]+", "", version)
            # Remove any pre-release or build metadata
            version = version.split("-", 1)[0]
            # Ensure version is properly formatted
            if repo.lower().startswith(("openzeppelin/", "chainlink/")) and not version.startswith(
                "v"
            ):
                version = f"v{version}"
            else:
                # For other repos, do not prepend 'v'
                pass

        # Build install target
        install_target = f"{repo}@{version}" if version else repo
        install_command = ["forge", "install", install_target, "--no-commit"]

        logger.info(f"Installing {install_target}")
        returncode, stdout, stderr = await run_command(install_command, temp_dir)
        if returncode != 0:
            logger.error(f"Failed to install {install_target}: {stderr}")
            continue  # Move on to the next dependency

        # Store remapping
        custom_remappings[import_path] = {
            "remapping": import_path,
            "folder_name": lib_folder,
        }

    logger.info("Dependencies installed successfully")
    return custom_remappings


async def generate_and_write_remappings(
    temp_dir: str, custom_remappings: Dict[str, Dict[str, str]]
) -> List[str]:
    remappings = []

    for import_path, data in custom_remappings.items():
        folder_name = data["folder_name"]
        remappings.append(f"{import_path}=lib/{folder_name}/")

    # Remove duplicates while preserving order
    remappings = list(dict.fromkeys(remappings))

    logger.info(f"Remappings generated: {remappings}")

    # Write remappings to file
    await write_remappings(temp_dir, remappings)
    logger.info("Remappings written successfully")

    return remappings


async def generate_remappings_with_foundry(temp_dir: str) -> List[str]:
    """
    Generates remappings using Foundry's 'forge remappings' command and writes them to remappings.txt.

    Args:
        temp_dir (str): The temporary directory where the project is located.

    Returns:
        List[str]: A list of remapping strings.
    """
    logger.info("Generating remappings with Foundry...")
    returncode, stdout, stderr = await run_command(["forge", "remappings"], cwd=temp_dir)
    if returncode != 0:
        # logger.error(f"Failed to generate remappings with Foundry: {stderr}")
        raise ValueError(f"Failed to generate remappings with Foundry: {stderr}")

    remappings = stdout.strip().splitlines()
    if not remappings:
        raise ValueError("No remappings were generated by Foundry.")

    logger.info(f"Remappings generated: {remappings}")

    # Write remappings to file
    await write_remappings(temp_dir, remappings)
    logger.info("Remappings written successfully using Foundry")

    return remappings
