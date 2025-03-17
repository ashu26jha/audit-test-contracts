import os
import shutil
import tempfile
from dataclasses import dataclass
from typing import Dict, List
from uuid import UUID

from api.v1.common.flatten_contracts import flatten_and_count_contracts
from api.v1.github.helpers.clone_repo import clone_repo
from api.v1.github.helpers.github_api_client import GitHubAPIClient
from api.v1.github.service import GitHubService
from core.db.repositories.scan import ScanRepository
from core.models.scan import CodeAnalysisResult
from core.utils.logger import logger
from core.utils.validate import validate_github_url

github_service = GitHubService()
github_api_client = GitHubAPIClient()


@dataclass
class GithubSourceInfo:
    """Data class to hold GitHub source information"""

    repo_dir: str
    temp_dir: str
    repo_info: dict
    commit_hash: str
    owner: str
    repo_name: str
    flattened_contracts: str
    lines_of_code: CodeAnalysisResult
    contract_contents: Dict[str, str]


async def get_contracts_per_github_url(
    repository_url: str,
    contract_files: List[str],
    access_token: str,
    scan_id: UUID,
    branch_name: str = "main",
) -> GithubSourceInfo:
    """
    Retrieves source code and metadata from a GitHub repository.

    Args:
        repository_url: GitHub repository URL
        contract_files: List of contract files to process
        access_token: GitHub access token
        scan_id: UUID of the current scan
        branch_name: Branch to use (defaults to "main")

    Returns:
        GithubSourceInfo object containing source code location and metadata

    Raises:
        Exception: Propagates any exceptions from GitHub operations or validation
    """
    temp_dir = None  # Initialize before try block

    try:
        # Validate GitHub URL
        validate_github_url(repository_url)

        # Parse owner and repo from URL
        owner, _ = github_api_client.parse_github_url(repository_url)

        # Get repository info
        repo_info = await github_service.get_github_repo_info(access_token, repository_url)

        # Create temporary directory
        temp_dir = tempfile.mkdtemp()

        # Clone repository
        repo_dir = await clone_repo(
            repository_url,
            temp_dir,
            access_token,
            branch_name,
        )

        # Get commit hash
        commit_hash = await github_service.get_commit_hash(
            access_token, repository_url, branch_name
        )

        # Update scan with commit hash
        await ScanRepository.update_scan_commit_hash(scan_id, commit_hash)

        # Flatten contracts
        flattened_contracts, lines_of_code, contract_contents = await flatten_and_count_contracts(
            contract_files,
            project_dir=repo_dir,
        )

        # Update scan in database
        await ScanRepository.update_scan_lines_of_code(scan_id, lines_of_code)
        await ScanRepository.update_scan_repo_name(scan_id, repo_info.repo_name)

        return GithubSourceInfo(
            repo_dir=repo_dir,
            temp_dir=temp_dir,
            repo_info=repo_info,
            commit_hash=commit_hash,
            owner=owner,
            repo_name=repo_info.repo_name,
            flattened_contracts=flattened_contracts,
            lines_of_code=lines_of_code,
            contract_contents=contract_contents,
        )

    except Exception as e:
        # Clean up temp directory on error
        if temp_dir is not None and os.path.exists(temp_dir):
            try:
                shutil.rmtree(temp_dir)
            except Exception as cleanup_error:
                logger.error(f"Error cleaning up temp directory: {cleanup_error}")
        raise e
