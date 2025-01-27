import tempfile
from datetime import datetime, timezone
from typing import Optional
from uuid import UUID

from fastapi import HTTPException

from api.v1.audit_agent.schema import AuditAgentRequest
from api.v1.common.flatten_contracts import flatten_contracts
from api.v1.common.lines_of_code import count_lines_of_code
from api.v1.github.helpers.clone_repo import clone_repo
from api.v1.github.service import GitHubService
from core.db.repositories.scan import ScanRepository
from core.models.scan import CodeAnalysisResult, Scan, ScanResult
from core.models.user import SubscriptionType, User
from core.utils.email_utils import send_error_email
from core.utils.profiles import Profiles
from core.utils.validate import (
    validate_contract_files,
    validate_github_url,
    validate_no_in_progress_scans,
    validate_user_has_github_token,
)

github_service = GitHubService()


class ScanInitializer:
    def __init__(
        self,
        user: User,
        request: AuditAgentRequest,
        scan_id: UUID,
    ):
        self.user = user
        self.request = request
        self.scan_id = scan_id
        self.repo_dir: Optional[str] = None
        self.temp_dir: Optional[str] = None
        self.repo_info = None
        self.branch_name = request.branchName or "main"

    async def validate_request(self) -> None:
        validate_user_has_github_token(self.user)
        validate_github_url(self.request.repositoryURL)
        validate_contract_files(self.request.contractFiles)
        await validate_no_in_progress_scans(self.user)

    async def clone_repository(self) -> None:
        # Create temporary directory for this scan
        self.temp_dir = tempfile.mkdtemp()

        # Clone repository once
        self.repo_dir = await clone_repo(
            self.request.repositoryURL,
            self.temp_dir,
            self.user.accessToken,
            self.branch_name,
        )

    async def fetch_repository_info(self):
        # Fetch repository info
        self.repo_info = await github_service.get_github_repo_info(
            self.user.accessToken, self.request.repositoryURL
        )

    def get_type_of_scan(self) -> str:
        # Get the type of scan from the request
        if not self.user.is_free:
            return SubscriptionType.FREE

        # Default to free user in case of None
        if self.user.subscription is None:
            return SubscriptionType.FREE
        # This ensure we put the correct type
        return self.user.subscription.type

    async def create_scan_record(self, scan_number: int):
        # Create and store the new scan with initial status 'pending' with type of scan
        type_of_scan = self.get_type_of_scan()
        new_scan = Scan(
            scan_id=self.scan_id,
            scan_number=scan_number,
            user_id=self.user.githubId,
            status="pending",
            startedAt=datetime.now(timezone.utc),
            contractFiles=self.request.contractFiles,
            repositoryURL=self.request.repositoryURL,
            repositoryName=self.repo_info.repo_name if self.repo_info else "",
            branchName=self.branch_name,
            type=type_of_scan,
        )
        await ScanRepository.store_scan(new_scan)

        # Create and store an initial empty scan result
        initial_scan_result = ScanResult(
            scan_id=self.scan_id,
            scan_number=scan_number,
            summary=None,
            info_message="Scan in progress",
            type=Profiles.NONE,
            total_findings=0,
            findings=[],
        )
        await ScanRepository.store_scan_result(initial_scan_result)

    async def fetch_commit_hash(self):
        # Fetch the commit hash using GitHub API
        try:
            commit_hash = await github_service.get_commit_hash(
                self.user.accessToken, self.request.repositoryURL, self.branch_name
            )

            # Update scan with commit hash
            await ScanRepository.update_scan_commit_hash(self.scan_id, commit_hash)

        except HTTPException:
            await ScanRepository.update_scan_failure(self.scan_id, "Failed to fetch commit hash")
            await send_error_email(self.user.email, self.scan_id)
            raise

    async def flatten_contracts(self) -> str:
        # Flatten contracts using the cloned repo
        flattened_contracts = await flatten_contracts(
            self.request.contractFiles,
            project_dir=self.repo_dir,
        )
        return flattened_contracts

    async def count_lines_of_code(self, flattened_contracts: str) -> CodeAnalysisResult:
        # Count lines of code
        lines_of_code = await count_lines_of_code(flattened_contracts)

        # Update scan with lines of code
        await ScanRepository.update_scan_lines_of_code(self.scan_id, lines_of_code)

        return lines_of_code
