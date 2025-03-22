import asyncio
import os
from typing import Dict, Optional
from uuid import UUID

from api.v1.common.docs_helpers import format_docs_for_prompt
from api.v1.github.helpers.github_api_client import GitHubAPIClient
from api.v1.scanner.cairo.helpers.scan_initializer import CairoScanInitializer
from api.v1.scanner.cairo.helpers.task_manager import CairoTaskManager
from api.v1.scanner.cairo.schema import CairoRequest, CairoScanContext
from api.v1.utilities.pdf.service import generate_and_send_pdf_from_scan
from core.db.connection import huey
from core.db.repositories.docs import DocsRepository
from core.db.repositories.user import UserRepository
from core.models.scan import Scan
from core.models.user import User
from core.scanners.base_scan_service import BaseScanService
from core.utils.logger import logger

github_api_client = GitHubAPIClient()


class CairoService(BaseScanService):
    """Service for handling Cairo scans."""

    async def create_context(self, scan_id: UUID, **kwargs) -> CairoScanContext:
        """Create context from audit agent request."""
        request: CairoRequest = kwargs["request"]
        user: User = kwargs["user"]

        # Format docs if provided
        formatted_docs = await self._format_docs(request, user) if request.docs else None

        # Get next scan number before creating context
        scan_number = await Scan.get_next_scan_number(str(user.githubId))

        return CairoScanContext(
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

    def create_initializer(self, context: CairoScanContext, user: User) -> CairoScanInitializer:
        """Create audit agent scan initializer."""
        return CairoScanInitializer(context, user)

    async def create_task_manager(self, context: CairoScanContext) -> CairoTaskManager:
        """Create audit agent task manager."""
        return CairoTaskManager(context)

    @staticmethod
    @huey.task()
    def perform_scan_background(context: CairoScanContext) -> None:
        """Background task to perform the audit agent scan."""

        logger.info(f"[Cairo] Starting background scan with ID: {context.scan_id}")

        os.environ["HUEY_WORKER"] = "1"

        try:
            service = CairoService()
            service.context = context  # Set context on the service instance
            asyncio.run(service.async_perform_scan(context))
        except Exception as e:
            logger.exception(f"[Cairo] Error in Huey task: {str(e)}")
            raise

    async def _format_docs(self, request: CairoRequest, user: User) -> Optional[Dict]:
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

    async def handle_scan_completion(self, context: CairoScanContext, _: int) -> None:
        # Generate PDF
        if context.user_email:
            try:
                user = await UserRepository.get_by_github_id(context.user_id)
                await generate_and_send_pdf_from_scan(user, context.scan_id)
            except Exception as e:
                logger.error(f"[Cairo] Failed to generate PDF: {str(e)}")
                # Don't fail the scan if PDF generation fails
        else:
            logger.warning(f"[Cairo] User {context.user_id} does not have an email address.")
