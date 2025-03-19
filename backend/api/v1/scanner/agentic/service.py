import asyncio
import os
from typing import Optional
from uuid import UUID

from api.v1.scanner.agentic.helpers.eliza_callback import send_callback_status
from api.v1.scanner.agentic.helpers.scan_initializer import AgenticScanInitializer
from api.v1.scanner.agentic.helpers.task_manager import AgenticTaskManager
from api.v1.scanner.agentic.schema import AgenticScanContext, PerAddressAgenticRequest
from api.v1.utilities.pdf.service import generate_and_send_agentic_pdf
from core.db.connection import huey
from core.models.user import User
from core.scanners.base_scan_service import BaseScanService
from core.utils.logger import logger


class AgenticService(BaseScanService):
    """Service for handling Agentic scans."""

    async def create_context(self, scan_id: UUID, **kwargs) -> AgenticScanContext:
        """Create context from agentic request."""
        request: PerAddressAgenticRequest = kwargs["request"]

        return AgenticScanContext(
            scan_id=scan_id,
            user_email=request.userEmail,
            user_name=request.userName,
            contract_address=request.contractAddress,
            chain_id=request.chainId,
            contract_files=[],  # Will be populated during initialization
            flattened_contracts=None,  # Will be populated during initialization
        )

    def create_initializer(
        self, context: AgenticScanContext, user: Optional[User] = None
    ) -> AgenticScanInitializer:
        """Create agentic scan initializer."""
        return AgenticScanInitializer(context)

    def create_task_manager(self, context: AgenticScanContext) -> AgenticTaskManager:
        """Create agentic task manager."""
        return AgenticTaskManager(context)

    @staticmethod
    @huey.task()
    def perform_scan_background(context: AgenticScanContext) -> None:
        """Background task to perform the agentic scan."""

        logger.info(f"[Agentic] Starting background scan with ID: {context.scan_id}")

        os.environ["HUEY_WORKER"] = "1"

        try:
            service = AgenticService()
            service.context = context  # Set context on the service instance
            asyncio.run(service.async_perform_scan(context))
        except Exception as e:
            logger.exception(f"[Agentic] Error in Huey task: {str(e)}")
            raise

    async def handle_scan_completion(self, context: AgenticScanContext, total_findings: int):
        """Handle scan-specific completion tasks (callbacks, PDF generation, etc)."""
        await send_callback_status(
            scan_id=context.scan_id,
            user_name=context.user_name,
            success=True,
            message=f"[Agentic] Scan completed successfully with {total_findings} findings",
        )

        if context.user_email:
            await generate_and_send_agentic_pdf(context.scan_id, context.user_email)
