import asyncio
import os
from typing import Dict, Optional
from uuid import UUID

from api.v1.audit_agent.helpers.scan_initializer import AuditAgentScanInitializer
from api.v1.audit_agent.helpers.task_manager import AuditAgentTaskManager
from api.v1.audit_agent.schema import AuditAgentRequest, AuditAgentScanContext
from api.v1.common.docs_helpers import format_docs_for_prompt
from api.v1.github.helpers.github_api_client import GitHubAPIClient
from api.v1.utilities.pdf.service import generate_and_send_pdf_from_scan
from core.db.connection import huey
from core.db.repositories.docs import DocsRepository
from core.db.repositories.user import UserRepository
from core.models.scan import Scan
from core.models.user import User
from core.scanners.base_scan_service import BaseScanService
from core.utils.logger import logger

github_api_client = GitHubAPIClient()


class AuditAgentService(BaseScanService):
    """Service for handling AuditAgent scans."""

    async def create_context(self, scan_id: UUID, **kwargs) -> AuditAgentScanContext:
        """Create context from audit agent request."""
        request: AuditAgentRequest = kwargs["request"]
        user: User = kwargs["user"]

        # Format docs if provided
        formatted_docs = await self._format_docs(request, user) if request.docs else None

        # Get next scan number before creating context
        scan_number = await Scan.get_next_scan_number(str(user.githubId))

        return AuditAgentScanContext(
            scan_id=scan_id,
            scan_number=scan_number,
            user_id=str(user.githubId),
            user_email=user.email,
            user_access_token=user.accessToken,
            is_subscription_scan=not user.is_free,
            repository_url=request.repositoryURL,
            branch_name=request.branchName,
            contract_files=request.contractFiles,
            formatted_docs=formatted_docs,
        )

    def create_initializer(
        self, context: AuditAgentScanContext, user: User
    ) -> AuditAgentScanInitializer:
        """Create audit agent scan initializer."""
        return AuditAgentScanInitializer(context, user)

    def create_task_manager(self, context: AuditAgentScanContext) -> AuditAgentTaskManager:
        """Create audit agent task manager."""
        return AuditAgentTaskManager(context)

    @staticmethod
    @huey.task()
    def perform_scan_background(context: AuditAgentScanContext) -> None:
        """Background task to perform the audit agent scan."""

        logger.info(f"[AuditAgent] Starting background scan with ID: {context.scan_id}")

        os.environ["HUEY_WORKER"] = "1"

        try:
            service = AuditAgentService()
            service.context = context  # Set context on the service instance
            asyncio.run(service.async_perform_scan(context))
        except Exception as e:
            logger.exception(f"[AuditAgent] Error in Huey task: {str(e)}")
            raise

    async def _format_docs(self, request: AuditAgentRequest, user: User) -> Optional[Dict]:
        """Format docs for the scan if applicable."""
        await DocsRepository.store_docs(
            repository_url=request.repositoryURL,
            user_id=user.githubId,
            docs=request.docs,
        )
        owner, repo = github_api_client.parse_github_url(request.repositoryURL)
        return await format_docs_for_prompt(
            request.docs,
            user.accessToken,
            owner,
            repo,
            request.branchName,
        )

    async def handle_scan_completion(self, context: AuditAgentScanContext, _: int) -> None:
        # Generate PDF
        if context.user_email:
            try:
                user = await UserRepository.get_by_github_id(context.user_id)
                await generate_and_send_pdf_from_scan(user, context.scan_id)
            except Exception as e:
                logger.error(f"[AuditAgent] Failed to generate PDF: {str(e)}")
                # Don't fail the scan if PDF generation fails
        else:
            logger.warning(f"[AuditAgent] User {context.user_id} does not have an email address.")
