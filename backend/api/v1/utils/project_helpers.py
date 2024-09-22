import json
import os
import re
from typing import Dict, List, Optional, Tuple

import toml
from api.v1.utils.forge_helpers import find_contract_folders
from common import logger

FOUNDRY_CONFIG = "foundry.toml"
HARDHAT_CONFIGS = [
    "hardhat.config.js",
    "hardhat.config.ts",
    "hardhat.config.cjs",
    "hardhat.config.mjs",
]
BROWNIE_CONFIGS = ["brownie-config.yaml", "brownie-config.json"]


def detect_project_structure(repo_dir: str) -> Tuple[str, List[str]]:
    project_types = [
        ("foundry", [FOUNDRY_CONFIG]),
        ("hardhat", HARDHAT_CONFIGS),
        ("brownie", BROWNIE_CONFIGS),
    ]

    for project_type, config_files in project_types:
        for config in config_files:
            if os.path.exists(os.path.join(repo_dir, config)):
                contract_folders = find_contract_folders(repo_dir)
                return project_type, contract_folders

    # If no specific config is found, assume it's a generic solidity project
    contract_folders = find_contract_folders(repo_dir)
    return "generic", contract_folders


def parse_dependencies(repo_dir: str, project_type: str) -> Dict[str, str]:
    dependencies = {}
    if project_type == "hardhat":
        package_json_path = os.path.join(repo_dir, "package.json")
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
                            imports = re.findall(r'import ["\'](.+?)["\'];', content)
                            for imp in imports:
                                # Extract package name
                                parts = imp.split("/")
                                if parts[0].startswith("@"):
                                    package = f"{parts[0]}/{parts[1]}"
                                else:
                                    package = parts[0]
                                if package in all_deps:
                                    dependencies[package] = all_deps[package]
                                else:
                                    dependencies[package] = "latest"
    elif project_type == "foundry":
        foundry_toml_path = os.path.join(repo_dir, "foundry.toml")
        if os.path.exists(foundry_toml_path):
            with open(foundry_toml_path, "r") as f:
                config = toml.load(f)
            deps = config.get("libs", {})
            for dep in deps:
                dependencies[dep] = deps[dep]

    return dependencies


def find_import_remappings(temp_dir: str) -> List[str]:
    remappings = []
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


def parse_solidity_version(file_path: str) -> Optional[str]:
    with open(file_path, "r") as file:
        content = file.read()
        pragma_pattern = r"pragma solidity\s*(\^|>=|<=|>|<)?\s*(\d+\.\d+\.\d+)"
        match = re.search(pragma_pattern, content)
        if match:
            version = match.group(2)
            return version
    return None


def find_solidity_version(temp_dir: str) -> str:
    logger.info(f"Searching for Solidity version in {temp_dir}")
    for root, _, files in os.walk(temp_dir):
        for file in files:
            if file.endswith(".sol"):
                file_path = os.path.join(root, file)
                logger.info(f"Checking file: {file_path}")
                version = parse_solidity_version(file_path)
                if version:
                    logger.info(f"Found Solidity version: {version}")
                    return version
                else:
                    logger.warning(f"No Solidity version found in {file_path}")
    logger.error("No Solidity version found in any file")
    return "0.8.27"  # Use the same default version as in detect_and_install_solc_version
