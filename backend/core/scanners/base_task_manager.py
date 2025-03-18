import asyncio
import gc
import itertools
from abc import ABC, abstractmethod
from typing import Dict, List, Optional, TypedDict, final

from api.v1.detectors.context_scan.service import run_context_scan_batch
from api.v1.detectors.fuzzer.service import FuzzerService
from api.v1.detectors.multi_agents.service import run_multi_agent
from api.v1.detectors.static_analyzer.service import run_static_analyzer
from api.v1.tools.service import query_and_search_service
from api.v1.utilities.ast_tree.schema import ProjectAST
from api.v1.utilities.ast_tree.service import generate_ast_for_project
from api.v1.utilities.invariants.schema import Invariant, InvariantsResponse
from api.v1.utilities.invariants.service import generate_invariants
from api.v1.utilities.summary.service import generate_summary
from config.settings import LLM_SCAN_1, LLM_SCAN_2, LLM_SCAN_3
from core.db.repositories.scan import ScanRepository
from core.models.scan import Finding, Scan
from core.schemas.context_protocols import BenchmarkContext, CompilationContext
from core.schemas.scan_schema import BaseScanContext, Detectors, TypeOfScan
from core.utils.logger import logger
from core.utils.profiles import Profiles

TOTAL_SCAN_TIMEOUT = 1200  # 20 minutes for entire scan
CONTEXT_SCAN_BATCH_SIZE = 3  # Number of context scans per batch

# Progress stage weights
PRE_DETECTOR_WEIGHT = 25  # Setup, cloning, etc. (0-25%)
DETECTOR_WEIGHT = 55  # Detectors (25-80%)
POST_DETECTOR_WEIGHT = 20  # Result processing (80-100%)


class TaskResults(TypedDict):
    combined_findings: List[Finding]
    summary_result: str
    detected_type: Profiles
    invariants: List[Invariant]


class BaseTaskManager(ABC):
    """Base class for all task managers with common functionality."""

    def __init__(self, context: BaseScanContext):
        self.context = context
        self.scan_id = context.scan_id
        self.scan: Optional[Scan] = None
        self.summary_result: Optional[str] = None
        self.detected_type: Optional[Profiles] = None
        self.invariants: Optional[InvariantsResponse] = None
        self.ast_tree: Optional[ProjectAST] = None
        self.duckduckgo_results: Optional[str] = None
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
        return [Profiles.DEFAULT, Profiles.DEFAULT_2, Profiles.NONE]

    @property
    def context_scan_batch_size(self) -> int:
        """
        Define the number of context scans to run in each batch.
        Can be overridden by child classes to customize batch size.
        Returns an integer representing the batch size.
        """
        return CONTEXT_SCAN_BATCH_SIZE

    @final
    async def execute_scan(self) -> TaskResults:
        """Main scan orchestrator."""
        try:
            # 1. Initialize detectors
            await self._initialize_detectors()

            # 2. Run summary, invariants, and AST tree generation in parallel
            summary_task = asyncio.create_task(generate_summary(self.context.flattened_contracts))
            invariants_task = asyncio.create_task(
                generate_invariants(
                    contracts_in_scope=self.context.contract_files,
                    flattened_contracts=self.context.flattened_contracts,
                    docs=getattr(self.context, "formatted_docs", None),
                )
            )

            # Only create AST tree task if context is CompilationContext and setup_result is not None
            ast_tree_task = None
            if (
                isinstance(self.context, CompilationContext)
                and self.context.setup_result is not None
            ):
                ast_tree_task = asyncio.create_task(
                    generate_ast_for_project(
                        repo_path=self.context.setup_result.project_dir,
                        contracts=self.context.contract_files,
                    )
                )

            # Wait for all tasks to complete
            results = await asyncio.gather(
                summary_task,
                invariants_task,
                *([] if ast_tree_task is None else [ast_tree_task]),
                return_exceptions=True,
            )

            # Process results and handle any exceptions
            # Check if summary task failed - this is critical and should fail the entire scan
            if isinstance(results[0], Exception):
                logger.error(
                    f"[TaskManager] Critical error in summary generation: {str(results[0])}"
                )
                raise results[0]  # Re-raise the summary exception to fail the scan

            # All tasks completed or handled exceptions internally
            self.summary_result, self.detected_type = results[0]
            self.invariants = results[1]
            self.ast_tree = results[2] if len(results) > 2 else None

            await ScanRepository.update_scan_progress(self.scan_id, 20)

            # 3. Run duckduckgo search
            self.duckduckgo_results = await query_and_search_service(
                contracts=self.context.flattened_contracts,
                num_queries=5,
                docs=getattr(self.context, "formatted_docs", None),
                ast_tree=self.ast_tree,
            )
            await ScanRepository.update_scan_progress(self.scan_id, 25)

            # 4. Execute detectors (failures handled silently)
            await self._run_detectors()

            # Clear memory after all detectors are complete
            self.context.flattened_contracts = None
            gc.collect()

            # 5. Gather results after all tasks are complete
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
            if detector == Detectors.CONTEXT_SCAN.value:
                await self._initialize_context_scan(detectors)
            elif detector == Detectors.STATIC_ANALYZER.value:
                await self._initialize_static_analysis(detectors)
            elif detector == Detectors.FUZZER.value:
                await self._initialize_fuzzing(detectors)
            elif detector == Detectors.MULTI_AGENTS.value:
                await self._initialize_multi_agent(detectors)

        # Save initial detectors to scan
        self.scan.detectors = detectors
        self.scan.total_detectors = len(detectors)
        self.scan.completed_detectors = 0

        # Calculate detector weights dynamically based on active detectors
        total_weight = DETECTOR_WEIGHT  # 55% for detectors
        self.detector_weights = {}

        # Reserve fixed weights for core detectors if they're active
        reserved_weights = {
            Detectors.STATIC_ANALYZER.value: 5,
            Detectors.FUZZER.value: 5,
            Detectors.MULTI_AGENTS.value: 30,
        }

        # Calculate how much weight is reserved for ACTIVE core detectors
        total_reserved = sum(
            weight for detector, weight in reserved_weights.items() if detector in detectors
        )

        # Calculate remaining weight for context scans
        remaining_weight = total_weight - total_reserved
        context_scan_count = sum(
            1 for d in detectors if d.startswith(f"{Detectors.CONTEXT_SCAN.value}_")
        )

        # Assign weights
        for detector in detectors:
            if detector in reserved_weights:
                # Core detectors get their fixed weights
                self.detector_weights[detector] = reserved_weights[detector]
            elif detector.startswith(f"{Detectors.CONTEXT_SCAN.value}_") and context_scan_count > 0:
                # Each context scan gets an equal share of remaining weight, rounded to 1 decimal
                context_scan_weight = round(remaining_weight / context_scan_count, 1)
                self.detector_weights[detector] = context_scan_weight

        await self.scan.save()

        logger.info(
            f"[TaskManager] Scan {self.scan_id} initialized with {len(detectors)} detectors. "
        )

    @final
    async def _initialize_context_scan(self, detectors: Dict) -> None:
        """Initialize context scan detector with LLM models."""
        profiles = self.context_scan_profiles
        models = self.context_scan_models

        for profile, model in itertools.product(profiles, models):
            detector_name = f"{Detectors.CONTEXT_SCAN.value}_{profile.value}_{model}"
            detectors[detector_name] = None
            self.context_scan_configs.append(
                {"detector_name": detector_name, "profile": profile, "model": model}
            )

    @final
    async def _initialize_static_analysis(self, detectors: Dict) -> None:
        """Initialize static analysis detector."""
        if isinstance(self.context, CompilationContext) and self.context.setup_result:
            detectors[Detectors.STATIC_ANALYZER.value] = None

    @final
    async def _initialize_fuzzing(self, detectors: Dict) -> None:
        """Initialize fuzzing detector."""
        if isinstance(self.context, CompilationContext) and self.context.setup_result:
            detectors[Detectors.FUZZER.value] = None

    @final
    async def _initialize_multi_agent(self, detectors: Dict) -> None:
        """Initialize multi-agent detector."""
        if isinstance(self.context, CompilationContext) and self.context.setup_result:
            detectors[Detectors.MULTI_AGENTS.value] = None

    # Run detectors

    @final
    async def _run_detectors(self) -> None:
        """Execute detectors in a semi-sequential order with controlled parallelism."""
        try:
            # Run detectors in parallel if they don't have dependencies
            detector_tasks = []

            # Static Analysis, Fuzzing, and Multi-Agents can run in parallel
            if Detectors.STATIC_ANALYZER.value in self.active_detectors:
                task = asyncio.create_task(self._run_static_analysis())
                detector_tasks.append(task)

            if Detectors.FUZZER.value in self.active_detectors:
                task = asyncio.create_task(self._run_fuzzing())
                detector_tasks.append(task)

            if Detectors.MULTI_AGENTS.value in self.active_detectors:
                task = asyncio.create_task(self._run_multi_agent())
                detector_tasks.append(task)

            # Wait for parallel detectors to complete
            if detector_tasks:
                await asyncio.gather(*detector_tasks, return_exceptions=True)

            # Run context scans last (they need summary but not other results)
            if Detectors.CONTEXT_SCAN.value in self.active_detectors:
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
                selected_contracts=self.context.contract_files,
                setup_result=self.context.setup_result,
            )
            self.task_results[Detectors.STATIC_ANALYZER.value] = result
            await self._update_progress(Detectors.STATIC_ANALYZER.value, True)
        except Exception as e:
            logger.error(f"[TaskManager] Static analysis failed: {str(e)}")
            self.task_results[Detectors.STATIC_ANALYZER.value] = e
            await self._update_progress(Detectors.STATIC_ANALYZER.value, False)

    @final
    async def _run_fuzzing(self) -> None:
        """Run fuzzing if setup is available."""
        if not isinstance(self.context, CompilationContext) or not self.context.setup_result:
            return

        try:
            result = await FuzzerService.run_fuzzer(
                github_url="",
                oauth_token="",
                selected_contracts=self.context.contract_files,
                flattened_contracts=self.context.flattened_contracts,
                setup_result=self.context.setup_result,
            )
            self.task_results[Detectors.FUZZER.value] = result
            await self._update_progress(Detectors.FUZZER.value, True)
        except Exception as e:
            logger.error(f"[TaskManager] Fuzzing failed: {str(e)}")
            self.task_results[Detectors.FUZZER.value] = e
            await self._update_progress(Detectors.FUZZER.value, False)

    @final
    async def _run_multi_agent(self) -> None:
        """Run multi-agent analysis."""
        if (
            not isinstance(self.context, CompilationContext)
            or not self.context.setup_result
            or not self.ast_tree
        ):
            return

        try:
            result = await run_multi_agent(
                contracts_in_scope=self.context.contract_files,
                ast_tree=self.ast_tree,
                project_dir=self.context.setup_result.repo_root,
                docs=getattr(self.context, "formatted_docs", None),
            )
            self.task_results[Detectors.MULTI_AGENTS.value] = result
            await self._update_progress(Detectors.MULTI_AGENTS.value, True)
        except Exception as e:
            logger.error(f"[TaskManager] Multi-agents analysis failed: {str(e)}")
            self.task_results[Detectors.MULTI_AGENTS.value] = e
            await self._update_progress(Detectors.MULTI_AGENTS.value, False)

    @final
    async def _run_context_scans(self) -> None:
        """Run context scans in sequential batches."""
        batch_size = self.context_scan_batch_size
        configs = self.context_scan_configs
        total_configs = len(configs)

        # Calculate how many batches we'll need
        total_batches = (total_configs + batch_size - 1) // batch_size
        logger.info(
            f"[TaskManager] Running {total_batches} context scan batches with batch size {batch_size}"
        )

        # Process all configs in batches sequentially
        for i in range(0, total_configs, batch_size):
            batch_end = min(i + batch_size, total_configs)
            batch = configs[i:batch_end]

            if batch:
                batch_num = (i // batch_size) + 1
                logger.info(
                    f"[TaskManager] Starting batch {batch_num}/{total_batches} with models: {[c['model'] for c in batch]} and profiles: {[c['profile'] for c in batch]}"
                )
                await self._run_context_scan_batch(batch)

                # Add a small delay between batches to avoid rate limits
                await asyncio.sleep(1)

    @final
    async def _run_context_scan_batch(self, batch_configs: List[Dict]) -> None:
        """Execute a batch of context scans and process results."""
        is_model_scan = False
        if (
            isinstance(self.context, BenchmarkContext)
            and self.context.type_of_scan == TypeOfScan.MODEL
        ):
            is_model_scan = True

        try:
            results = await run_context_scan_batch(
                contracts=self.context.flattened_contracts,
                summary=self.summary_result,
                docs=None if is_model_scan else getattr(self.context, "formatted_docs", None),
                invariants=None if is_model_scan else self.invariants,
                duckduckgo_results=(
                    self.duckduckgo_results
                    if batch_configs[0]["profile"] == Profiles.NONE
                    else None
                ),
                batch_configs=batch_configs,
            )

            # Process successful results
            if results:
                for config, result in zip(batch_configs, results):
                    detector_name = config["detector_name"]
                    self.task_results[detector_name] = result
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
                for finding in findings:
                    finding.Detector = detector_name
                findings_by_detector[detector_name] = findings
                combined_findings.extend(findings)
            else:
                findings_by_detector[detector_name] = []
                logger.error(f"Context scan failed - Detector: {detector_name}")

        # Process static analysis results
        if Detectors.STATIC_ANALYZER.value in self.task_results:
            static_result = self.task_results[Detectors.STATIC_ANALYZER.value]
            if not isinstance(static_result, Exception):
                try:
                    static_findings = static_result.findings
                    for finding in static_findings:
                        finding.Detector = Detectors.STATIC_ANALYZER.value
                    findings_by_detector[Detectors.STATIC_ANALYZER.value] = static_findings
                    combined_findings.extend(static_findings)
                except Exception as e:
                    logger.error(f"Static analysis results processing failed: {str(e)}")
                    findings_by_detector[Detectors.STATIC_ANALYZER.value] = []
            else:
                logger.error(f"Static analysis failed: {static_result}")
                findings_by_detector[Detectors.STATIC_ANALYZER.value] = []

        # Process fuzzing results
        if Detectors.FUZZER.value in self.task_results:
            fuzzing_result = self.task_results[Detectors.FUZZER.value]
            if not isinstance(fuzzing_result, Exception):
                fuzzing_findings = getattr(fuzzing_result.data, "findings", [])
                for finding in fuzzing_findings:
                    finding.Detector = Detectors.FUZZER.value
                findings_by_detector[Detectors.FUZZER.value] = fuzzing_findings
                combined_findings.extend(fuzzing_findings)
            else:
                logger.error(f"Fuzzing failed: {fuzzing_result}")
                findings_by_detector[Detectors.FUZZER.value] = []

        # Process multi-agents results
        if Detectors.MULTI_AGENTS.value in self.task_results:
            multi_agents_result = self.task_results[Detectors.MULTI_AGENTS.value]
            if not isinstance(multi_agents_result, Exception):
                multi_agents_findings = multi_agents_result.findings
                for finding in multi_agents_findings:
                    finding.Detector = Detectors.MULTI_AGENTS.value
                findings_by_detector[Detectors.MULTI_AGENTS.value] = multi_agents_findings
                combined_findings.extend(multi_agents_findings)
            else:
                logger.error(f"Multi-agents analysis failed: {multi_agents_result}")
                findings_by_detector[Detectors.MULTI_AGENTS.value] = []

        # Update scan status in database
        if self.scan:
            await self.scan.save()

        return {
            "combined_findings": combined_findings,
            "summary_result": self.summary_result,
            "detected_type": self.detected_type,
            "invariants": self.invariants.invariants,
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

        # Calculate progress as an integer percentage, up to maximum of 80%
        # This leaves room for result_processor to continue from 80% to 100%
        current_progress = PRE_DETECTOR_WEIGHT
        for name, completed in self.scan.detectors.items():
            if completed is not None:
                weight = self.detector_weights.get(name, 0)
                current_progress += weight

        # Convert to integer and scale to max 80%
        max_detector_progress = 80
        progress_int = min(int(current_progress), max_detector_progress)

        # If all detectors are complete, set progress to 80% (not 100%)
        # so that result_processor can continue from there
        if self.scan.completed_detectors == self.scan.total_detectors:
            progress_int = max_detector_progress

        self.scan.progress = max(self.scan.progress, progress_int)
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
        context_scan_detectors = [
            d for d in self.active_detectors if d.startswith(f"{Detectors.CONTEXT_SCAN.value}_")
        ]
        for detector in context_scan_detectors:
            if detector in self.task_results:
                task = self.task_results[detector]
                if isinstance(task, asyncio.Task):
                    running_tasks.append((task, f"{Detectors.CONTEXT_SCAN.value}_{detector}"))

        # Add static analysis task if running
        if Detectors.STATIC_ANALYZER.value in self.task_results:
            task = self.task_results[Detectors.STATIC_ANALYZER.value]
            if isinstance(task, asyncio.Task):
                running_tasks.append((task, Detectors.STATIC_ANALYZER.value))

        # Add fuzzing task if running
        if Detectors.FUZZER.value in self.task_results:
            task = self.task_results[Detectors.FUZZER.value]
            if isinstance(task, asyncio.Task):
                running_tasks.append((task, Detectors.FUZZER.value))

        # Add multi-agents task if running
        if Detectors.MULTI_AGENTS.value in self.task_results:
            task = self.task_results[Detectors.MULTI_AGENTS.value]
            if isinstance(task, asyncio.Task):
                running_tasks.append((task, Detectors.MULTI_AGENTS.value))

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
