import os
from typing import Optional

from core.utils.logger import logger


class SolidityFileStorage:
    """Handles Solidity contract storage using file paths, reading from disk when needed."""

    def __init__(self, repo_root: str):
        """
        Args:
            repo_root (str): The root directory where the repo was cloned (e.g. /tmp/tmp51tt55t7/2022-05-backd/protocol/contracts)
        """
        # Get project root by counting 3 levels from temp directory
        parts = repo_root.split(os.sep)
        temp_index = parts.index("tmp")  # Find where the temp directory starts
        project_root_parts = parts[
            : temp_index + 3
        ]  # Get parts up to project root (tmp + random + project)
        self.project_root = os.sep.join(project_root_parts)

    def get_contract_path(self, contract_path: str) -> str:
        """
        Returns the absolute file path for a given contract path.
        Contract paths are relative to project root.

        Args:
            contract_path: The relative path to the contract

        Returns:
            str: The absolute path to the contract
        """
        absolute_path = os.path.join(self.project_root, contract_path)
        return absolute_path

    def read_contract(self, contract_path: str) -> Optional[str]:
        """
        Reads the Solidity contract file from disk when needed.

        Args:
            contract_path: The relative path to the contract

        Returns:
            Optional[str]: The contract content or None if not found

        Raises:
            ContractError: In API routes, when the file is not found
        """
        file_path = self.get_contract_path(contract_path)

        try:
            with open(file_path, "r", encoding="utf-8") as f:
                content = f.read()
                return content
        except FileNotFoundError:
            logger.warning(f"[SolidityFileStorage] File not found: {file_path}")
            return None  # Contract file not found
