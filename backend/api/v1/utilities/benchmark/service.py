import asyncio
import os
from typing import Optional
from uuid import UUID

from api.v1.utilities.benchmark.helpers.scan_initializer import BenchmarkScanInitializer
from api.v1.utilities.benchmark.helpers.task_manager import BenchmarkTaskManager
from api.v1.utilities.benchmark.schema import BenchmarkScanContext, BenchmarkScanRequest
from core.db.connection import huey
from core.models.user import User
from core.scanners.base_scan_service import BaseScanService
from core.utils import logger


class BenchmarkService(BaseScanService):
    """Service for handling benchmark scans."""

    async def create_context(self, scan_id: UUID, **kwargs) -> BenchmarkScanContext:
        """Create context from benchmark request."""
        request: BenchmarkScanRequest = kwargs["request"]

        return BenchmarkScanContext(
            scan_id=scan_id,
            repository_url=request.repositoryURL,
            branch_name=request.branchName,
            contract_files=request.contractFiles,
            type_of_scan=request.typeOfScan,
            model=request.model,
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
    @huey.task(retries=2, retry_delay=10)
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
        pass
