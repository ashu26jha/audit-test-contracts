from datetime import datetime, timezone

from api.v1.github.service import GitHubService
from core.db.repositories.scan import ScanRepository
from core.models.scan import Scan
from core.scanners.base_scan_initializer import BaseScanInitializer
from core.schemas.scan_schema import ScanType
from core.utils.errors import ValidationError
from core.utils.validate import (
    validate_contract_files,
    validate_free_scan_limit,
    validate_github_url,
    validate_no_in_progress_scans,
    validate_user_has_github_token,
)

github_service = GitHubService()


class AuditAgentScanInitializer(BaseScanInitializer):
    """AuditAgent-specific scan initialization logic."""

    async def validate_request(self) -> None:
        """Validate repository and contract files."""
        validate_user_has_github_token(self.user)
        validate_github_url(self.context.repository_url)
        validate_contract_files(self.context.contract_files)
        await validate_no_in_progress_scans(self.user)

        if self.user.is_free:
            free_scan_status = await validate_free_scan_limit(self.user.githubId)
            if not free_scan_status.is_allowed:
                raise ValidationError(
                    message="Free scan limit reached.",
                    details="Free scan limit reached. Please wait for the next available scan or upgrade your subscription.",
                )

    async def create_scan_record(self) -> None:
        """Create the initial scan record with audit-agent-specific details."""

        type_of_scan = self.get_scan_subscription_type()

        # Create scan record
        new_scan = Scan(
            scan_id=self.scan_id,
            scan_type=ScanType.AUDIT_AGENT,
            scan_number=self.context.scan_number,
            user_id=self.context.user_id,
            status="pending",
            startedAt=datetime.now(timezone.utc),
            contractFiles=self.context.contract_files,
            repositoryURL=self.context.repository_url,
            repositoryName=self.context.repository_name if self.context.repository_name else "",
            branchName=self.context.branch_name,
            type=type_of_scan,
        )

        # Store scan and create initial result
        await ScanRepository.store_scan(new_scan)
