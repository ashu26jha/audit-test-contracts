import os
from pathlib import Path
from typing import List, Optional

from common import logger
from config.solidity import FOUNDRY_CONFIGS, HARDHAT_CONFIGS


class ProjectConfig:
    """Represents a detected project configuration"""

    def __init__(self, root_dir: str, project_type: str, config_file: str):
        self.root_dir = root_dir
        self.project_type = project_type
        self.config_file = config_file
        self.distance_to_contracts = float("inf")

    def __str__(self):
        return f"ProjectConfig(type={self.project_type}, root={self.root_dir})"


async def detect_project_config(repo_dir: str, contract_files: List[str]) -> ProjectConfig:
    """Detects the most appropriate project configuration based on contract locations."""
    # Get absolute paths for contract directories
    contract_dirs = {os.path.dirname(os.path.join(repo_dir, file)) for file in contract_files}
    configs: List[ProjectConfig] = []

    # Check sub-repo directories
    configs.extend(_check_sub_repo_configs(repo_dir))

    # Check contract directories and their parents
    for contract_dir in contract_dirs:
        configs.extend(_check_contract_dir_configs(contract_dir, repo_dir))

    # Check repository root
    if root_config := _check_root_config(repo_dir):
        configs.append(root_config)

    if not configs:
        logger.info("No project config found, defaulting to Foundry at repo root")
        return ProjectConfig(repo_dir, "foundry", "")

    configs = _calculate_config_distances(configs, contract_dirs)
    selected_config = configs[0]

    logger.info(
        f"Selected project config: {selected_config.project_type} at {selected_config.root_dir}"
    )
    return selected_config


def _find_config_file(directory: str, config_files: List[str]) -> Optional[str]:
    """Checks if any of the config files exist in the directory"""
    for config in config_files:
        config_path = os.path.join(directory, config)
        if os.path.exists(config_path):
            return config_path
    return None


def _calculate_path_distance(path1: str, path2: str) -> int:
    """Calculates the directory distance between two paths"""
    path1_parts = Path(path1).parts
    path2_parts = Path(path2).parts

    # Find common prefix
    common = 0
    for p1, p2 in zip(path1_parts, path2_parts):
        if p1 != p2:
            break
        common += 1

    return len(path1_parts) + len(path2_parts) - 2 * common


def _check_sub_repo_configs(repo_dir: str) -> List[ProjectConfig]:
    """Check sub-repo directories for project configurations."""
    configs = []
    sub_repo_dirs = ["contracts", "foundry", "hardhat"]

    for sub_dir in sub_repo_dirs:
        check_dir = os.path.join(repo_dir, sub_dir)
        if not os.path.exists(check_dir):
            continue

        if foundry_config := _find_config_file(check_dir, FOUNDRY_CONFIGS):
            configs.append(ProjectConfig(check_dir, "foundry", foundry_config))
        elif hardhat_config := _find_config_file(check_dir, HARDHAT_CONFIGS):
            configs.append(ProjectConfig(check_dir, "hardhat", hardhat_config))

    return configs


def _check_contract_dir_configs(contract_dir: str, repo_dir: str) -> List[ProjectConfig]:
    """Check contract directory and its parents for project configurations."""
    configs = []
    current_dir = contract_dir

    while current_dir and os.path.commonprefix([current_dir, repo_dir]) == repo_dir:
        if foundry_config := _find_config_file(current_dir, FOUNDRY_CONFIGS):
            configs.append(ProjectConfig(current_dir, "foundry", foundry_config))
            break
        elif hardhat_config := _find_config_file(current_dir, HARDHAT_CONFIGS):
            configs.append(ProjectConfig(current_dir, "hardhat", hardhat_config))
            break
        current_dir = os.path.dirname(current_dir)

    return configs


def _check_root_config(repo_dir: str) -> Optional[ProjectConfig]:
    """Check repository root for project configuration."""
    if foundry_config := _find_config_file(repo_dir, FOUNDRY_CONFIGS):
        return ProjectConfig(repo_dir, "foundry", foundry_config)
    elif hardhat_config := _find_config_file(repo_dir, HARDHAT_CONFIGS):
        return ProjectConfig(repo_dir, "hardhat", hardhat_config)
    return None


def _calculate_config_distances(
    configs: List[ProjectConfig], contract_dirs: set
) -> List[ProjectConfig]:
    """Calculate and sort configs based on distance to contract directories."""
    if not configs:
        return configs

    for config in configs:
        total_distance = sum(
            _calculate_path_distance(config.root_dir, contract_dir)
            for contract_dir in contract_dirs
        )
        config.distance_to_contracts = total_distance / len(contract_dirs)

    # Sort: Foundry first, then by distance to contracts
    configs.sort(key=lambda x: (0 if x.project_type == "foundry" else 1, x.distance_to_contracts))
    return configs
