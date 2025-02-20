import asyncio
import gc
import itertools
from abc import ABC, abstractmethod
from typing import Dict, List, Optional, TypedDict, final

from api.v1.detectors.context_scan.schema import ContextScanResponse
from api.v1.detectors.context_scan.service import run_context_scan_batch
from api.v1.detectors.fuzzer.service import FuzzerService
from api.v1.detectors.static_analyzer.service import run_static_analyzer
from api.v1.utilities.summary.service import generate_summary
from config.settings import LLM_SCAN_1, LLM_SCAN_2, LLM_SCAN_3
from core.db.repositories.scan import ScanRepository
from core.models.scan import Finding, Scan
from core.schemas.context_protocols import CompilationContext
from core.schemas.scan_schema import BaseScanContext
from core.utils.logger import logger
from core.utils.profiles import Profiles

TOTAL_SCAN_TIMEOUT = 900  # 15 minutes for entire scan
CONTEXT_SCAN_BATCH_SIZE = 3  # Constants for batch processing

# Progress stage weights
PRE_DETECTOR_WEIGHT = 25  # Setup, cloning, etc. (0-25%)
DETECTOR_WEIGHT = 50  # Detectors (25-75%)
POST_DETECTOR_WEIGHT = 25  # Deduplication, cleanup (75-100%)


class TaskResults(TypedDict):
    combined_findings: List[Finding]
    summary_result: str
    detected_type: Profiles


class BaseTaskManager(ABC):
    """Base class for all task managers with common functionality."""

    def __init__(self, context: BaseScanContext):
        self.context = context
        self.scan_id = context.scan_id
        self.flattened_contracts = context.flattened_contracts
        self.contract_files = context.contract_files
        self.scan: Optional[Scan] = None
        self.summary_result: Optional[str] = None
        self.detected_type: Optional[Profiles] = None
        self.task_results: Dict = {}
        self.task_detector_names: List[str] = []  # Track detector order
        self.active_detectors: List[str] = []  # Track enabled detectors
        self.context_scan_configs: List[Dict] = []
        self.detector_weights: Dict[str, float] = {}

    @property
    @abstractmethod
    def available_detectors(self) -> Dict[str, bool]:
        """
        Define available detectors and their default enabled state.
        Override in each scan type.
        Example:
        return {
            "context_scan": True,
            "static_analysis": True,
            "fuzzing": False,
        }
        """
        pass

    @property
    def context_scan_models(self) -> List[str]:
        """
        Define the LLM models to use for context scanning.
        Can be overridden by child classes to customize model selection.
        Returns a list of model identifiers.
        """
        return [LLM_SCAN_1, LLM_SCAN_2, LLM_SCAN_3]

    @property
    def context_scan_profiles(self) -> List[Profiles]:
        """
        Define the profiles to use for context scanning.
        Can be overridden by child classes to customize profile selection.
        Returns a list of profiles.
        """
        return [Profiles.DEFAULT, Profiles.DEFAULT_2]

    @final
    async def execute_scan(self) -> TaskResults:
        """Main scan orchestrator."""
        try:
            # 1. Initialize detectors
            await self._initialize_detectors()

            # 2. Generate summary (constant task)
            self.summary_result, self.detected_type = await generate_summary(
                self.flattened_contracts
            )

            # 3. Execute detectors (failures handled silently)
            await self._run_detectors()

            # Clear memory after all detectors are complete
            self.flattened_contracts = None
            gc.collect()

            # 4. Gather results after all tasks are complete
            return await self._gather_results()

        except Exception as e:
            logger.error(f"[TaskManager] Critical error in scan execution: {str(e)}")
            raise  # Re-raise to be handled by service

    # Initialize detectors

    @final
    async def _initialize_detectors(self, **kwargs) -> None:
        """Initialize scan and configure progress tracking."""
        # Fetch scan document
        self.scan = await ScanRepository.get_scan(self.scan_id)

        # Configure active detectors from available ones
        enabled_detectors = {
            name: kwargs.get(name, enabled) for name, enabled in self.available_detectors.items()
        }
        self.active_detectors = [name for name, enabled in enabled_detectors.items() if enabled]

        # Initialize detectors based on active ones
        detectors: Dict[str, bool | None] = {}
        for detector in self.active_detectors:
            if detector == "context_scan":
                await self._initialize_context_scan(detectors)
            elif detector == "static_analysis":
                await self._initialize_static_analysis(detectors)
            elif detector == "fuzzing":
                await self._initialize_fuzzing(detectors)

        # Save initial detectors to scan
        self.scan.detectors = detectors
        self.scan.total_detectors = len(detectors)
        self.scan.completed_detectors = 0

        # Calculate detector weights dynamically based on active detectors
        total_weight = DETECTOR_WEIGHT  # 50% for detectors
        self.detector_weights = {}

        # Reserve fixed weights for core detectors if they're active
        reserved_weights = {"static_analyzer": 10, "fuzzer": 10}

        # Calculate how much weight is reserved for core detectors
        total_reserved = sum(
            weight for detector, weight in reserved_weights.items() if detector in detectors
        )

        # Remaining weight to distribute among context scans
        remaining_weight = total_weight - total_reserved
        context_scan_count = sum(1 for d in detectors if d.startswith("context_scan_"))

        # Distribute weights
        if context_scan_count > 0:
            context_scan_weight = remaining_weight / context_scan_count
            for detector in detectors:
                if detector.startswith("context_scan_"):
                    self.detector_weights[detector] = context_scan_weight
                else:
                    # Assign reserved weights for core detectors
                    self.detector_weights[detector] = reserved_weights.get(detector, 0)
        else:
            # If no context scans, distribute remaining weight among other detectors
            other_detector_weight = remaining_weight / len(detectors) if detectors else 0
            for detector in detectors:
                self.detector_weights[detector] = reserved_weights.get(
                    detector, other_detector_weight
                )

        await self.scan.save()

        logger.info(
            f"[TaskManager] Scan {self.scan_id} initialized with {len(detectors)} detectors. "
        )

    @final
    async def _initialize_context_scan(self, detectors: Dict) -> None:
        """Initialize context scan detector with LLM models."""
        profiles = self.context_scan_profiles
        models = self.context_scan_models

        for i, (profile, model) in enumerate(itertools.product(profiles, models), 1):
            detector_name = f"context_scan_{i}"
            detectors[detector_name] = None
            self.context_scan_configs.append(
                {"detector_name": detector_name, "profile": profile, "model": model}
            )

    @final
    async def _initialize_static_analysis(self, detectors: Dict) -> None:
        """Initialize static analysis detector."""
        if isinstance(self.context, CompilationContext) and self.context.setup_result:
            detectors["static_analyzer"] = None

    @final
    async def _initialize_fuzzing(self, detectors: Dict) -> None:
        """Initialize fuzzing detector."""
        if isinstance(self.context, CompilationContext) and self.context.setup_result:
            detectors["fuzzer"] = None

    # Run detectors

    @final
    async def _run_detectors(self) -> None:
        """Execute detectors in a semi-sequential order with controlled parallelism."""
        try:
            # Run detectors in parallel if they don't have dependencies
            detector_tasks = []

            # Static Analysis and Fuzzing can run in parallel
            if "static_analysis" in self.active_detectors:
                task = asyncio.create_task(self._run_static_analysis())
                detector_tasks.append(task)

            if "fuzzing" in self.active_detectors:
                task = asyncio.create_task(self._run_fuzzing())
                detector_tasks.append(task)

            # Wait for static analysis and fuzzing to complete
            if detector_tasks:
                await asyncio.gather(*detector_tasks, return_exceptions=True)

            # Run context scans last (they need summary but not other results)
            if "context_scan" in self.active_detectors:
                await self._run_context_scans()

        except Exception as e:
            logger.error(f"[TaskManager] Error in detector execution: {str(e)}")

    @final
    async def _run_static_analysis(self) -> None:
        """Run static analysis if setup is available."""
        if not isinstance(self.context, CompilationContext) or not self.context.setup_result:
            return

        try:
            result = await run_static_analyzer(
                github_url="",
                oauth_token="",
                selected_contracts=self.contract_files,
                setup_result=self.context.setup_result,
            )
            self.task_results["static_analyzer"] = result
            await self._update_progress("static_analyzer", True)
        except Exception as e:
            logger.error(f"[TaskManager] Static analysis failed: {str(e)}")
            self.task_results["static_analyzer"] = e
            await self._update_progress("static_analyzer", False)

    @final
    async def _run_fuzzing(self) -> None:
        """Run fuzzing if setup is available."""
        if not isinstance(self.context, CompilationContext) or not self.context.setup_result:
            return

        try:
            result = await FuzzerService.run_fuzzer(
                github_url="",
                oauth_token="",
                selected_contracts=self.contract_files,
                flattened_contracts=self.flattened_contracts,
                setup_result=self.context.setup_result,
            )
            self.task_results["fuzzer"] = result
            await self._update_progress("fuzzer", True)
        except Exception as e:
            logger.error(f"[TaskManager] Fuzzing failed: {str(e)}")
            self.task_results["fuzzer"] = e
            await self._update_progress("fuzzer", False)

    @final
    async def _run_context_scans(self) -> None:
        """Run context scans in parallel batches."""
        batch_size = CONTEXT_SCAN_BATCH_SIZE
        configs = self.context_scan_configs
        total_configs = len(configs)

        for i in range(0, total_configs, batch_size * 2):
            batch1 = configs[i : i + batch_size]  # noqa: E203
            batch2 = configs[i + batch_size : i + (batch_size * 2)]  # noqa: E203

            tasks = []
            for batch_num, batch in enumerate([batch1, batch2], 1):
                if batch:
                    logger.info(
                        f"[TaskManager] Starting batch {batch_num} with models: {[c['model'] for c in batch]}"
                    )
                    task = asyncio.create_task(self._run_context_scan_batch(batch))
                    tasks.append(task)

            await asyncio.gather(*tasks, return_exceptions=True)

    @final
    async def _run_context_scan_batch(self, batch_configs: List[Dict]) -> None:
        """Execute a batch of context scans and process results."""
        try:
            results = await run_context_scan_batch(
                self.flattened_contracts,
                self.summary_result,
                getattr(self.context, "docs", None),
                batch_configs,
            )

            # Process successful results
            if results:
                for config, result in zip(batch_configs, results):
                    detector_name = config["detector_name"]
                    # Validate and store result
                    self.task_results[detector_name] = ContextScanResponse.model_validate(result)
                    self.task_detector_names.append(detector_name)
                    await self._update_progress(detector_name, True)

        except Exception as e:
            logger.error(f"[TaskManager] Batch context scan failed: {str(e)}")
            # Handle failures for all detectors in the batch
            for config in batch_configs:
                detector_name = config["detector_name"]
                self.task_results[detector_name] = e
                self.task_detector_names.append(detector_name)
                await self._update_progress(detector_name, False)

    # Gather results | Update progress | Cleanup running tasks

    @final
    async def _gather_results(self) -> TaskResults:
        """Gather and process results from all detectors."""
        combined_findings: List[Finding] = []
        findings_by_detector = {}

        # Process context scan results in order they were received
        for detector_name in self.task_detector_names:
            result = self.task_results.get(detector_name)

            if not isinstance(result, (Exception, asyncio.TimeoutError)):
                findings = result.findings
                findings_by_detector[detector_name] = findings
                combined_findings.extend(findings)
            else:
                findings_by_detector[detector_name] = []
                logger.error(f"Context scan failed - Detector: {detector_name}")

        # Process static analysis results
        if "static_analyzer" in self.task_results:
            static_result = self.task_results["static_analyzer"]
            if not isinstance(static_result, Exception):
                try:
                    slither_findings = static_result.static_analysis_output.findings
                    findings_by_detector["static_analyzer"] = slither_findings
                    combined_findings.extend(slither_findings)
                except Exception as e:
                    logger.error(f"Static analysis results processing failed: {str(e)}")
                    findings_by_detector["static_analyzer"] = []
            else:
                logger.error(f"Static analysis failed: {static_result}")
                findings_by_detector["static_analyzer"] = []

        # Process fuzzing results
        if "fuzzer" in self.task_results:
            fuzzing_result = self.task_results["fuzzer"]
            if not isinstance(fuzzing_result, Exception):
                fuzzing_findings = getattr(fuzzing_result.data, "findings", [])
                findings_by_detector["fuzzer"] = fuzzing_findings
                combined_findings.extend(fuzzing_findings)
            else:
                logger.error(f"Fuzzing failed: {fuzzing_result}")
                findings_by_detector["fuzzer"] = []

        # Update scan status in database
        if self.scan:
            await self.scan.save()

        return {
            "combined_findings": combined_findings,
            "summary_result": self.summary_result,
            "detected_type": self.detected_type,
        }

    @final
    async def _update_progress(self, detector_name: str, success: bool) -> None:
        """
        Update scan progress when a detector completes.

        Args:
            detector_name: Name of the detector that completed
            success: Whether the detector completed successfully
        """
        if not self.scan:
            logger.warning(
                f"[TaskManager] Cannot update progress for {detector_name}: scan not initialized"
            )
            return

        # Validate detector exists
        if detector_name not in self.detector_weights:
            logger.error(f"[TaskManager] Unknown detector {detector_name} - cannot update progress")
            return

        self.scan.completed_detectors += 1
        self.scan.detectors[detector_name] = success

        current_progress = PRE_DETECTOR_WEIGHT
        for name, completed in self.scan.detectors.items():
            if completed is not None:
                weight = self.detector_weights.get(name, 0)
                current_progress += weight

        self.scan.progress = max(self.scan.progress, current_progress)
        await self.scan.save()

    @final
    async def _cleanup_running_tasks(self) -> None:
        """Clean up any running tasks and release resources."""
        cleanup_errors = []

        async def safe_cancel(task: asyncio.Task, task_name: str) -> None:
            """Helper function to safely cancel a task."""
            if not task or task.done():
                return

            try:
                task.cancel()
                await task
            except asyncio.CancelledError:
                # This is expected when cancelling tasks
                pass
            except Exception as e:
                error_msg = f"Error during {task_name} cleanup: {str(e)}"
                cleanup_errors.append(error_msg)
                logger.error(error_msg)

        # Track all running tasks that need cleanup
        running_tasks = []

        # Add context scan tasks if any are running
        context_scan_detectors = [d for d in self.active_detectors if d.startswith("context_scan_")]
        for detector in context_scan_detectors:
            if detector in self.task_results:
                task = self.task_results[detector]
                if isinstance(task, asyncio.Task):
                    running_tasks.append((task, f"context_scan_{detector}"))

        # Add static analysis task if running
        if "static_analyzer" in self.task_results:
            task = self.task_results["static_analyzer"]
            if isinstance(task, asyncio.Task):
                running_tasks.append((task, "static_analyzer"))

        # Add fuzzing task if running
        if "fuzzer" in self.task_results:
            task = self.task_results["fuzzer"]
            if isinstance(task, asyncio.Task):
                running_tasks.append((task, "fuzzer"))

        # Cancel all running tasks
        for task, name in running_tasks:
            await safe_cancel(task, name)

        # Log cleanup results
        if cleanup_errors:
            logger.warning(
                f"[TaskManager] Task cleanup completed with {len(cleanup_errors)} errors"
            )
            for error in cleanup_errors:
                logger.warning(error)

        # Force garbage collection after cleanup
        gc.collect()
