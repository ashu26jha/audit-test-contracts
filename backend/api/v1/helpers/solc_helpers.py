import os
import re
from typing import List, Optional

from packaging import version

from api.v1.helpers.forge_helpers import run_command_sync
from common import logger


def detect_and_install_solc_versions(temp_dir: str) -> str:
    versions = find_solidity_versions(temp_dir)
    for solc_version in versions:
        install_solc_version(solc_version)

    # Return the latest (highest) version
    return max(versions, key=lambda v: version.parse(v))


def install_solc_version(version: str) -> None:
    # Attempt to list installed versions
    returncode, stdout, stderr = run_command_sync(["solc-select", "versions"], ".")
    if returncode != 0:
        logger.warning(f"Could not list installed Solc versions: {stderr}")
        installed_versions = []
        version_set = False
    else:
        installed_versions = [
            line.strip("* ").strip() for line in stdout.strip().split("\n") if line.strip()
        ]
        version_set = any(line.startswith("*") for line in stdout.strip().split("\n"))

    # Install the required version if not already installed
    if version not in installed_versions:
        logger.info(f"Installing Solc version {version}...")
        returncode, stdout, stderr = run_command_sync(["solc-select", "install", version], ".")
        if returncode != 0:
            logger.warning(f"Failed to install Solc version {version}: {stderr}")
            logger.info(f"Contracts requiring version {version} may not compile.")
            return
        else:
            logger.info(f"Solc version {version} installed successfully.")

    else:
        logger.info(f"Solc version {version} is already installed.")

    # Set the Solc version if none is set
    if not version_set:
        returncode, stdout, stderr = run_command_sync(["solc-select", "use", version], ".")
        if returncode != 0:
            logger.warning(f"Failed to set Solc version {version}: {stderr}")
        else:
            logger.info(f"Solc version {version} is now active.")


def parse_solidity_version(file_path: str) -> Optional[str]:
    with open(file_path, "r") as file:
        content = file.read()
        pragma_pattern = r"pragma solidity\s+([^;]+);"
        match = re.search(pragma_pattern, content)
        if match:
            version_spec = match.group(1).strip()
            # Extract all version numbers
            version_numbers = re.findall(r"\d+\.\d+\.\d+", version_spec)
            if version_numbers:
                # Use the lowest version in the range
                version_in_file = min(version_numbers, key=lambda v: version.parse(v))
                return version_in_file
    return None


def find_solidity_versions(temp_dir: str) -> List[str]:
    versions = set()
    search_dirs = [
        os.path.join(temp_dir, d)
        for d in ["src", "contracts"]
        if os.path.exists(os.path.join(temp_dir, d))
    ]
    for dir_path in search_dirs:
        for root, _, files in os.walk(dir_path):
            for file in files:
                if file.endswith(".sol"):
                    file_path = os.path.join(root, file)
                    version_str = parse_solidity_version(file_path)
                    if version_str:
                        versions.add(version_str)

    if versions:
        version_list = sorted(versions, key=lambda v: version.parse(v))
        return version_list
    else:
        # If no version found, default to 0.8.27
        logger.warning(
            "No Solidity version found in src/ or contracts/. Using default version 0.8.27"
        )
        return ["0.8.27"]
