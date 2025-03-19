import asyncio
import os
from typing import Dict, Optional
from uuid import UUID

from api.v1.common.docs_helpers import format_docs_for_benchmark
from api.v1.github.helpers.github_api_client import GitHubAPIClient
from api.v1.scanner.benchmark.helpers.scan_initializer import BenchmarkScanInitializer
from api.v1.scanner.benchmark.helpers.task_manager import BenchmarkTaskManager
from api.v1.scanner.benchmark.schema import BenchmarkScanContext, BenchmarkScanRequest
from core.db.connection import huey
from core.models.user import User
from core.scanners.base_scan_service import BaseScanService
from core.utils import logger

github_api_client = GitHubAPIClient()


class BenchmarkService(BaseScanService):
    """Service for handling benchmark scans."""

    async def create_context(self, scan_id: UUID, **kwargs) -> BenchmarkScanContext:
        """Create context from benchmark request."""
        request: BenchmarkScanRequest = kwargs["request"]

        # Format docs if provided
        formatted_docs = await self._format_docs(request) if request.docs else None

        return BenchmarkScanContext(
            scan_id=scan_id,
            repository_url=request.repositoryURL,
            branch_name=request.branchName,
            contract_files=request.contractFiles,
            type_of_scan=request.typeOfScan,
            model=request.model,
            mode=request.mode,
            formatted_docs=formatted_docs,
        )

    def create_initializer(
        self, context: BenchmarkScanContext, user: Optional[User] = None
    ) -> BenchmarkScanInitializer:
        """Create benchmark scan initializer."""
        return BenchmarkScanInitializer(context, user)

    def create_task_manager(self, context: BenchmarkScanContext) -> BenchmarkTaskManager:
        """Create benchmark task manager."""
        return BenchmarkTaskManager(context)

    @staticmethod
    @huey.task()
    def perform_scan_background(context: BenchmarkScanContext) -> None:
        """Background task to perform a new benchmark scan."""

        logger.info(f"[Benchmark] Starting background scan with ID: {context.scan_id}")

        os.environ["HUEY_WORKER"] = "1"

        try:
            service = BenchmarkService()
            service.context = context  # Set context on the service instance
            asyncio.run(service.async_perform_scan(context))
        except Exception as e:
            logger.exception(f"[Benchmark] Error in Huey task: {str(e)}")
            raise

    async def handle_scan_completion(self, context: BenchmarkScanContext, _: int) -> None:
        """Handle scan completion. Not needed for benchmark scans."""
        pass

    async def _format_docs(self, request: BenchmarkScanRequest) -> Optional[Dict]:
        """Format docs for the scan if applicable."""

        return await format_docs_for_benchmark(request.docs)
