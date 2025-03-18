from abc import ABC, abstractmethod
from typing import Any, Dict, List, Optional, TypeVar, final
from uuid import UUID

from fastapi import HTTPException
from langfuse.decorators import langfuse_context, observe

from api.v1.common.get_contracts_per_address import get_contracts_per_address
from api.v1.common.get_contracts_per_github_url import get_contracts_per_github_url
from api.v1.common.setup_environment import cleanup_environment, setup_environment
from core.db.connection import close_database, init_database
from core.db.repositories.scan import ScanRepository
from core.models.scan import Finding
from core.models.user import User
from core.scanners.base_scan_initializer import BaseScanInitializer
from core.scanners.base_task_manager import BaseTaskManager
from core.scanners.payment_handler import PaymentHandler
from core.scanners.result_processor import BaseResultsProcessor
from core.schemas.context_protocols import (
    BenchmarkContext,
    ChainContext,
    CompilationContext,
    GitHubContext,
    UserContext,
)
from core.schemas.scan_schema import BaseScanContext, ScanType, TypeOfScan
from core.utils.errors import InitializationError, UnsupportedOperationError
from core.utils.logger import logger
from core.utils.profiles import Profiles
from core.utils.validate import validate_subscription_limits

T = TypeVar("T", bound=BaseScanInitializer)
M = TypeVar("M", bound=BaseTaskManager)


class BaseScanService(ABC):
    """Base class for all scan services."""

    def __init__(self):
        self.context: Optional[BaseScanContext] = None
        self.initializer: Optional[BaseScanInitializer] = None
        self.task_manager: Optional[BaseTaskManager] = None
        self.payment_handler: Optional[PaymentHandler] = None
        self.results_processor: Optional[BaseResultsProcessor] = None

    @final
    async def create_scan(self, scan_id: UUID, scan_type: ScanType, **kwargs) -> Dict[str, Any]:
        """
        Main entry point for scan creation.
        Handles the high-level flow of creating and starting a scan.
        """
        user = kwargs.get("user")

        try:
            # 1. Create context
            self.context = await self.create_context(scan_id, **kwargs)

            # 2. Initialize scan
            self.initializer = self.create_initializer(self.context, user)
            await self.initializer.initialize()

            # 3. Initialize payment handler
            self.payment_handler = PaymentHandler(self.context)
            await self.payment_handler.initialize_payment()

            # 4. Get source code based on scan type
            if self.context.scan_type == ScanType.AGENTIC:
                await self._get_source_code_from_chain(self.context)
            else:
                await self._get_source_code_from_github(self.context)

            # 5. Start scan in background with Huey Queue & task priority
            priority = self._get_scan_priority(user)
            self.perform_scan_background(self.context, priority=priority)

            return {"scan_id": str(scan_id)}

        except Exception as e:
            error_msg = f"[{scan_type.value}] Failed to create scan: {str(e)}"
            await self.handle_scan_failure(error_msg, send_email=False)
            raise HTTPException(status_code=500, detail=error_msg) from e

    @abstractmethod
    async def create_context(self, scan_id: UUID, **kwargs) -> BaseScanContext:
        """Create scan context from request parameters."""
        pass

    @abstractmethod
    def create_initializer(self, context: BaseScanContext, user: Optional[User] = None) -> T:
        """Create appropriate initializer instance."""
        pass

    @abstractmethod
    def create_task_manager(self, context: BaseScanContext) -> M:
        """Create appropriate task manager instance."""
        pass

    @abstractmethod
    def perform_scan_background(context: BaseScanContext) -> None:
        """
        Background task to perform the scan.

        Runs in a separate Huey worker process with database connection management.
        Handles the complete scan lifecycle including summary generation, context scans,
        result processing, and PDF generation.

        Args:
            context (BaseScanContext): Complete context for the scan including
                contract information and configuration.

        Note:
            This method should be implemented as a static method in child classes because
            Huey needs to serialize task arguments, and instance methods cannot be
            properly serialized. Each implementation should create a new instance
            of the service within this method if needed.
        """
        pass

    @abstractmethod
    async def handle_scan_completion(self, context: BaseScanContext, total_findings: int) -> None:
        """Handle scan-specific completion tasks (callbacks, PDF generation, etc)."""
        pass

    @final
    def create_payment_handler(self) -> PaymentHandler:
        """Create payment handler when needed."""
        return PaymentHandler(self.context)

    @final
    def update_payment_handler(self, total_findings: int) -> None:
        """Update payment handler with findings after scan."""
        self.payment_handler = PaymentHandler(self.context, total_findings)

    @final
    def create_results_processor(
        self,
        combined_findings: List[Finding],
        summary_result: str,
        detected_type: Profiles,
        contract_contents: Dict[str, str] = None,
    ) -> BaseResultsProcessor:
        """Create results processor with scan results."""
        return BaseResultsProcessor(
            scan_id=self.context.scan_id,
            user_id=self.context.user_id,
            contract_files=self.context.contract_files,
            combined_findings=combined_findings,
            summary_result=summary_result,
            detected_type=detected_type,
            contract_contents=contract_contents,
        )

    @final
    async def handle_scan_failure(self, error_msg: str, send_email: Optional[bool] = True) -> None:
        """
        Central error handling for all scan types.
        Handles cleanup, payment updates, and notifications.
        """
        try:
            logger.error(error_msg)

            if not self.context:
                raise InitializationError("Context is not set")

            # 1. Update scan status
            await ScanRepository.update_scan_failure(self.context.scan_id, error_msg)

            # 2. Handle payment failure
            if self.payment_handler:
                await self.payment_handler.finalize_payment()

            # 3. Cleanup resources
            if self.task_manager:
                await self.task_manager._cleanup_running_tasks()

            # 4. Handle credit refund for subscription scans
            if self.context.is_subscription_scan:
                from api.v1.payments.helpers.credits import CreditHelper

                await CreditHelper.refund_credit(self.context.user_id, self.context.scan_id)

            # 5. Send error notification
            if isinstance(self.context, UserContext) and send_email:
                if self.context.user_email and self.context.scan_type == ScanType.AUDIT_AGENT:
                    from core.utils.email_utils import send_error_email

                    await send_error_email(self.context.user_email, self.context.scan_id)

            # 6. Send error notification for Agentic
            if self.context.scan_type == ScanType.AGENTIC and isinstance(self.context, UserContext):
                from api.v1.agentic.helpers.eliza_callback import send_callback_status

                await send_callback_status(
                    scan_id=self.context.scan_id,
                    user_name=self.context.user_name,
                    success=False,
                    message=error_msg,
                )

        except Exception as e:
            logger.error(
                f"[{self.context.scan_type.value}] Error during failure handling: {str(e)}"
            )
            # Even if cleanup fails, ensure the scan is marked as failed
            await ScanRepository.update_scan_failure(
                self.context.scan_id, f"Original error: {error_msg}. Cleanup failed: {str(e)}"
            )

    @final
    async def _get_source_code_from_github(self, context: BaseScanContext):
        """Get source code from GitHub and update context."""
        if not isinstance(context, GitHubContext):
            raise UnsupportedOperationError(
                f"Context type {type(context).__name__} does not support GitHub operations"
            )

        if not isinstance(context, CompilationContext):
            raise UnsupportedOperationError(
                f"Context type {type(context).__name__} does not support compilation operations"
            )

        if not isinstance(context, UserContext):
            raise UnsupportedOperationError(
                f"Context type {type(context).__name__} does not support user operations"
            )

        github_info = await get_contracts_per_github_url(
            repository_url=context.repository_url,
            contract_files=context.contract_files,
            access_token=context.user_access_token,
            scan_id=context.scan_id,
            branch_name=context.branch_name,
        )

        # Validate subscription limits for AuditAgent scans
        if context.scan_type == ScanType.AUDIT_AGENT:
            await validate_subscription_limits(
                context.user_id, context.contract_files, github_info.lines_of_code.total_lines
            )

        # Update context with GitHub info
        context.commit_hash = github_info.commit_hash
        context.flattened_contracts = github_info.flattened_contracts
        context.contract_contents = (
            github_info.contract_contents
        )  # Store contract contents dictionary
        context.repo_dir = github_info.repo_dir
        context.temp_dir = github_info.temp_dir
        context.repository_name = github_info.repo_name

    @final
    async def _get_source_code_from_chain(self, context: BaseScanContext):
        """Get source code from blockchain and update context."""
        if not isinstance(context, ChainContext):
            raise UnsupportedOperationError(
                f"Context type {type(context).__name__} does not support blockchain operations"
            )

        contract_info = await get_contracts_per_address(
            context.scan_id, context.contract_address, context.chain_id
        )

        # Update context with contract info
        context.flattened_contracts = contract_info.flattened_contracts
        context.contract_files = contract_info.contract_files
        context.contracts_dict = contract_info.contracts_dict

        # Update contractFiles in Scan model
        await ScanRepository.update_scan_contract_files(context.scan_id, context.contract_files)

    @final
    def _get_scan_priority(self, user: Optional[User]) -> int:
        """Get the priority for the scan based on the user type."""
        if not self.context:
            return 10  # Default priority if no context

        if self.context.scan_type == ScanType.AGENTIC:
            return 6  # Default priority for Agentic scans

        if self.context.scan_type == ScanType.BENCHMARK:
            return 10  # Default priority for benchmarks

        # For AuditAgent scans, verify user context
        if not isinstance(self.context, UserContext):
            return 10  # Default to lowest priority if no user context

        if user and user.is_enterprise:
            return 1  # Highest priority
        elif user and user.is_pro:
            return 5  # Medium priority
        return 10  # Lowest priority (default)

    @final
    @observe(name="background_scan")
    async def async_perform_scan(self, context: BaseScanContext) -> None:
        """Execute the scan in background with proper error handling."""
        try:
            # Initialize database
            await init_database()

            # Update scan status to 'in_progress'
            await ScanRepository.update_scan_status(context.scan_id, "in_progress")
            await ScanRepository.update_scan_progress(context.scan_id, 10)

            # Install dependencies and compile the project - fails silently (Agentic and model benchmark excluded)
            is_model_scan = False
            if isinstance(context, BenchmarkContext):
                is_model_scan = context.type_of_scan == TypeOfScan.MODEL

            if (
                isinstance(context, CompilationContext)
                and isinstance(context, GitHubContext)
                and not is_model_scan
            ):
                try:
                    context.setup_result = await setup_environment(
                        context.repository_url,
                        context.repo_dir,
                        context.user_access_token,
                        context.branch_name,
                        context.contract_files,
                    )
                    # Update progress after successful setup (15%)
                    await ScanRepository.update_scan_progress(context.scan_id, 15)
                except Exception as e:
                    logger.error(f"[{context.scan_type.value}] Environment setup failed: {str(e)}")
                    # Continue with setup_result as None

            # TaskManager: execute scan & gather results
            self.task_manager = self.create_task_manager(context)
            results = await self.task_manager.execute_scan()

            # BaseResultsProcessor: Aggregate, deduplicate, and mitigate results
            result_processor = BaseResultsProcessor(
                scan_id=context.scan_id,
                user_id=context.user_id,
                contract_files=context.contract_files,
                combined_findings=results["combined_findings"],
                summary_result=results["summary_result"],
                detected_type=results["detected_type"],
                invariants=results["invariants"],
                contract_contents=context.contract_contents,
            )
            total_findings_after_dedup = await result_processor.process_results()

            langfuse_context.update_current_trace(session_id=str(context.scan_id))

            # Update scan status to 'completed' and include total_findings
            await ScanRepository.update_scan_status(
                context.scan_id, "completed", total_findings_after_dedup
            )

            # Handle payment processing using PaymentHandler
            payment_handler = PaymentHandler(context, total_findings_after_dedup)
            await payment_handler.finalize_payment()

            # Hook for scan-specific completion handling
            await self.handle_scan_completion(context, total_findings_after_dedup)

            logger.info(
                f"[{context.scan_type.value}] Scan ID {context.scan_id} completed successfully with {total_findings_after_dedup} findings"
            )

        except Exception as e:
            error_msg = f"[{context.scan_type.value}] Error during scan execution: {str(e)}"
            await self.handle_scan_failure(error_msg)
            raise  # Re-raise to ensure Huey marks the task as failed

        finally:
            await close_database()
            if context and hasattr(context, "temp_dir") and hasattr(context, "repo_dir"):
                await cleanup_environment(context.temp_dir, context.repo_dir)
