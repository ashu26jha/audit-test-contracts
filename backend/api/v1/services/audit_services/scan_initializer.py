import tempfile
from datetime import datetime, timezone
from typing import Optional
from uuid import UUID

from fastapi import HTTPException

from api.v1.helpers.audit_helpers import update_scan_failure
from api.v1.helpers.lines_of_code_helpers import count_lines_of_code
from api.v1.models.scan import CodeAnalysisResult, Scan, ScanResult
from api.v1.models.user import User
from api.v1.schemas import audit_agent_schema
from api.v1.services import scan_history_service
from api.v1.services.audit_services.flatten_contracts import flatten_contracts
from api.v1.services.github_service import GitHubService
from common.clone_repo import clone_repo
from common.profiles import Profiles
from common.validate import (
    validate_contract_files,
    validate_github_url,
    validate_no_in_progress_scans,
    validate_no_unpaid_scans,
    validate_subscription,
    validate_user_has_github_token,
)
from config.settings import ENVIRONMENT

github_service = GitHubService()


class ScanInitializer:
    def __init__(
        self,
        user: User,
        request: audit_agent_schema.AuditAgentRequest,
        scan_id: UUID,
    ):
        self.user = user
        self.request = request
        self.scan_id = scan_id
        self.scan_number: Optional[int] = None
        self.repo_dir: Optional[str] = None
        self.temp_dir: Optional[str] = None
        self.repo_info = None
        self.branch_name = request.branchName or "main"

    async def validate_request(self) -> bool:
        validate_user_has_github_token(self.user)
        validate_github_url(self.request.repositoryURL)
        validate_contract_files(self.request.contractFiles)
        await validate_no_in_progress_scans(self.user)
        if ENVIRONMENT != "development":
            await validate_no_unpaid_scans(self.user)

        return await validate_subscription(self.user)

    async def clone_repository(self):
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

    async def create_scan_record(self):
        # Get the next scan_number for this user
        self.scan_number = await Scan.get_next_scan_number(self.user.githubId)

        # Create and store the new scan with initial status 'pending'
        new_scan = Scan(
            scan_id=self.scan_id,
            scan_number=self.scan_number,
            user_id=self.user.githubId,
            status="pending",
            startedAt=datetime.now(timezone.utc),
            contractFiles=self.request.contractFiles,
            repositoryURL=self.request.repositoryURL,
            repositoryName=self.repo_info.repo_name if self.repo_info else "",
            branchName=self.branch_name,
        )
        await scan_history_service.store_scan(new_scan)

        # Create and store an initial empty scan result
        initial_scan_result = ScanResult(
            scan_id=self.scan_id,
            scan_number=self.scan_number,
            summary=None,
            info_message="Scan in progress",
            type=Profiles.NONE,
            total_findings=0,
            findings=[],
        )
        await scan_history_service.store_scan_result(initial_scan_result)

    async def fetch_commit_hash(self):
        # Fetch the commit hash using GitHub API
        try:
            commit_hash = await github_service.get_commit_hash(
                self.user.accessToken, self.request.repositoryURL, self.branch_name
            )
        except HTTPException as e:
            await update_scan_failure(self.user.email, self.scan_id, f"Scan failed: {e.detail}")
            raise HTTPException(
                status_code=e.status_code,
                detail=f"Failed to fetch commit hash: {e.detail}",
            ) from e

        if not commit_hash:
            error_msg = "Failed to fetch commit hash. Check if branch exists."
            await update_scan_failure(
                self.user.email,
                self.scan_id,
                error_msg,
            )
            raise HTTPException(
                status_code=500,
                detail=error_msg,
            )

        # Update scan with commit hash
        scan = await scan_history_service.get_scan(self.scan_id)
        if scan:
            scan.commitHash = commit_hash
            await scan.save()

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
        scan = await scan_history_service.get_scan(self.scan_id)
        if scan:
            scan.linesOfCode = lines_of_code
            await scan.save()

        return lines_of_code
