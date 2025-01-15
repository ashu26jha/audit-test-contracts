import asyncio
import gc
from datetime import datetime
from http.client import HTTPException
from typing import Any, Dict, List, Optional, TypedDict

from api.v1.audit_agent.schema import ScanContext
from api.v1.detectors.context_scan.schema import ContextScanResponse

# from api.v1.detectors.fuzzer.service import FuzzerService
from api.v1.detectors.context_scan.service import run_context_scan
from api.v1.detectors.static_analyzer.service import run_static_analyzer
from api.v1.utilities.summary.service import generate_summary
from config.settings import LLM_SCAN_1, LLM_SCAN_2, LLM_SCAN_3
from core.db.repositories.scan import ScanRepository
from core.models.scan import Finding, Scan
from core.schemas.audit_agent_schema import SetupResult
from core.utils.email_utils import send_error_email
from core.utils.logger import logger
from core.utils.process_pool import ProcessPoolManager
from core.utils.profiles import Profiles

TOTAL_SCAN_TIMEOUT = 900  # 15 minutes for entire scan
CONTEXT_SCANS_TIMEOUT = 300  # 10 minutes per context scan

# Progress stage weights
PRE_DETECTOR_WEIGHT = 25  # Setup, cloning, etc. (0-25%)
DETECTOR_WEIGHT = 50  # Detectors (25-75%)
POST_DETECTOR_WEIGHT = 25  # Deduplication, cleanup (75-100%)


class TaskManager:

    def __init__(
        self,
        context: ScanContext,
        flattened_contracts: str,
        setup_result: Optional[SetupResult],
        detected_profile: Profiles,
    ):
        self.scan_id = context.scan_id
        self.user_email = context.user_email
        self.flattened_contracts = flattened_contracts
        self.selected_contracts = context.contract_files
        self.docs = context.formatted_docs
        self.setup_result = setup_result
        self.detected_profile = detected_profile
        self.scan: Optional[Scan] = None
        self.context_scan_configs: List[Dict[str, Any]] = []
        self.context_scan_tasks: List[asyncio.Task] = []
        self.task_detector_names: List[str] = []
        self.result_index: int = 0

        # Initialize optional tasks
        self.static_analysis_task: Optional[asyncio.Task] = None
        self.fuzzing_task: Optional[asyncio.Task] = None

        self.task_results = {}
        self.error_email_sent = False
        self.process_pool = ProcessPoolManager.get_instance()

    async def initialize_scan(self):
        # Fetch the scan document to update detectors
        self.scan = await ScanRepository.get_scan(self.scan_id)

        # Initialize detectors
        detectors: Dict[str, Optional[bool]] = {}
        active_detectors = 0

        # Prepare profiles and models
        profiles = [Profiles.DEFAULT, Profiles.DEFAULT_2]
        models = [LLM_SCAN_1, LLM_SCAN_2, LLM_SCAN_3]

        # Generate detector names for context scans
        for profile in profiles:
            for model in models:
                detector_name = f"context_scan_{active_detectors + 1}"
                detectors[detector_name] = None
                self.context_scan_configs.append(
                    {"detector_name": detector_name, "profile": profile, "model": model}
                )
                active_detectors += 1

        # Add static analyzer if setup was successful
        detectors["static_analyzer"] = None
        if self.setup_result:
            active_detectors += 1

        # Add fuzzer if setup successful
        detectors["fuzzer"] = None
        if self.setup_result and self.fuzzing_task:
            active_detectors += 1

        # Save initial detectors to scan
        if self.scan:
            self.scan.detectors = detectors
            self.scan.total_detectors = active_detectors
            self.scan.completed_detectors = 0
            self.scan.progress = PRE_DETECTOR_WEIGHT
            await self.scan.save()

        # Initialize detector weights dynamically
        total_weight = DETECTOR_WEIGHT
        context_scan_count = len(self.context_scan_configs)

        # Create dynamic weights dictionary
        dynamic_weights = {}

        if self.setup_result:
            dynamic_weights["static_analyzer"] = 10
            total_weight -= 10

            if self.fuzzing_task:
                dynamic_weights["fuzzer"] = 10
                total_weight -= 10

        # Distribute remaining weight among context scans
        context_scan_weight = total_weight / context_scan_count
        for i in range(context_scan_count):
            # flake8: noqa: E226
            dynamic_weights[f"context_scan_{i+1}"] = context_scan_weight

        # Store the dynamic weights in the instance
        self.detector_weights = dynamic_weights

        logger.info(f"Scan {self.scan_id} initialized with {active_detectors} detectors. ")

    async def start_tasks(self):
        try:
            async with asyncio.timeout(TOTAL_SCAN_TIMEOUT):
                await self._execute_tasks()
        except asyncio.TimeoutError:
            logger.error(f"Scan {self.scan_id} exceeded maximum time of {TOTAL_SCAN_TIMEOUT}s")
            # Handle timeout - mark remaining tasks as failed

    async def _execute_tasks(self):
        """
        Sequential flow with strict ordering and verification
        """
        try:
            # 1. Summary Generation
            try:
                self.summary_result, self.detected_type = await generate_summary(
                    self.flattened_contracts
                )
            except Exception as e:
                logger.exception(f"Summary generation failed: {str(e)}")
                await ScanRepository.update_scan_failure(self.scan_id, "Summary generation failed")
                await self._send_error_email_once()
                raise HTTPException(
                    status_code=500,
                    detail="Internal server error during summary generation.",
                ) from e

            # 2. Static Analysis & Fuzzing (if setup available)
            if self.setup_result:
                # Static Analysis with silent failure
                try:
                    # Create and await static analysis
                    self.static_analysis_task = asyncio.create_task(
                        run_static_analyzer(
                            "",
                            "",
                            self.selected_contracts,
                            self.setup_result,
                        )
                    )

                    # Monitor task
                    monitor_task = asyncio.create_task(
                        self._monitor_task(
                            self.static_analysis_task,
                            "static_analyzer",
                        )
                    )

                    # Wait for both execution and monitoring to complete with timeout
                    await asyncio.wait(
                        [self.static_analysis_task, monitor_task],
                        timeout=300,  # 5 minutes timeout
                        return_when=asyncio.ALL_COMPLETED,
                    )
                except Exception as e:
                    logger.error(f"Static analysis failed silently: {str(e)}")
                    # Store the error but continue execution
                    self.task_results["static_analyzer"] = e
                    await self.update_progress("static_analyzer", False)

                # Force garbage collection after static analysis
                gc.collect()
                await asyncio.sleep(1)

                # Fuzzing with silent failure (commented but handled)
                try:
                    # Create fuzzing task (TODO: Uncomment when fuzzing is ready)
                    # self.fuzzing_task = asyncio.create_task(
                    #     fuzzing_service.run_fuzzer(
                    #         "",
                    #         "",
                    #         self.selected_contracts,
                    #         self.flattened_contracts,
                    #         self.setup_result,
                    #     )
                    # )

                    # Monitor fuzzing task
                    if self.fuzzing_task:
                        monitor_task = asyncio.create_task(
                            self._monitor_task(
                                self.fuzzing_task,
                                "fuzzer",
                            )
                        )

                        # Wait for both execution and monitoring to complete with timeout
                        await asyncio.wait(
                            [self.fuzzing_task, monitor_task],
                            timeout=300,  # 5 minutes timeout
                            return_when=asyncio.ALL_COMPLETED,
                        )
                except Exception as e:
                    logger.error(f"Fuzzing failed silently: {str(e)}")
                    # Store the error but continue execution
                    self.task_results["fuzzer"] = e
                    await self.update_progress("fuzzer", False)

                # Force garbage collection after fuzzing
                gc.collect()
                await asyncio.sleep(1)

            # 3. Context Scans - Strict batching with verification
            await self._run_context_scans_in_batches()

        except asyncio.TimeoutError as e:
            logger.error(f"Scan {self.scan_id} exceeded maximum time of {TOTAL_SCAN_TIMEOUT}s")
            await self._cleanup_running_tasks()
            await ScanRepository.update_scan_failure(self.scan_id, "Scan timed out")
            await self._send_error_email_once()
            raise HTTPException(
                status_code=500, detail=f"Scan timed out after {TOTAL_SCAN_TIMEOUT}s"
            ) from e
        except Exception as e:
            logger.error(f"Error in task execution: {str(e)}")
            raise

    async def _monitor_task(self, task: asyncio.Task, detector_name: str):
        try:
            result = await task
            # Store the result
            self.task_results[detector_name] = result
            if isinstance(result, Exception):
                await self.update_progress(detector_name, False)
            else:
                await self.update_progress(detector_name, True)
        except Exception as e:
            logger.error(f"Task {detector_name} failed: {str(e)}")
            self.task_results[detector_name] = e  # Store the error
            await self.update_progress(detector_name, False)

    async def _run_context_scans_in_batches(self):
        """Run context scans in batches of 2 using process pool."""
        batch_size = 3

        # Process context scans in batches
        for i in range(0, len(self.context_scan_configs), batch_size):
            batch = self.context_scan_configs[i : i + batch_size]
            batch_tasks = []

            # Create tasks for current batch
            for config in batch:
                detector_name = config["detector_name"]

                # Create task for the context scan
                task = asyncio.create_task(self.run_context_scan_with_retry(config))

                # Store task metadata
                batch_tasks.append((task, detector_name))
                self.context_scan_tasks.append(task)
                self.task_detector_names.append(detector_name)

                # Create monitoring task
                monitor_task = asyncio.create_task(self._monitor_task(task, detector_name))

                # Add monitor task to batch tasks
                batch_tasks.append((monitor_task, f"{detector_name}_monitor"))

            # Wait for current batch to complete before starting next batch
            try:
                # Wait for all tasks in batch (both execution and monitoring)
                await asyncio.gather(*(task for task, _ in batch_tasks), return_exceptions=True)

                # Force cleanup between batches
                gc.collect()

            except Exception as e:
                logger.error(f"Error processing batch: {str(e)}")
                continue

    async def run_context_scan_with_retry(self, config):
        """Run a single context scan with retry logic"""
        start_time = datetime.now()
        retry_count = 0
        max_retries = 2

        while retry_count < max_retries:
            try:
                # Check remaining time for this context scan
                elapsed = (datetime.now() - start_time).total_seconds()
                if elapsed >= CONTEXT_SCANS_TIMEOUT:
                    raise TimeoutError("Context scan exceeded maximum time")

                response_dict = await self.process_pool.run_in_process(
                    run_context_scan,
                    self.summary_result,
                    self.docs,
                    self.flattened_contracts,
                    config["profile"],
                    config["model"],
                )

                return ContextScanResponse.model_validate(response_dict)

            except Exception as e:
                retry_count += 1
                if retry_count >= max_retries:
                    raise
                logger.warning(
                    f"Context scan attempt {retry_count}/{max_retries} failed for {config['profile']} with {config['model']}"
                    f"Error: {str(e)}"
                )
                await asyncio.sleep(5)

    class GatherResults(TypedDict):
        combined_findings: List[Finding]
        summary_result: str
        detected_type: Profiles

    async def gather_results(self) -> GatherResults:
        # Use stored results instead of awaiting tasks again
        results = []

        # Gather context scan results
        for detector_name in self.task_detector_names:
            results.append(self.task_results.get(detector_name))

        # Add static analysis result if it exists
        if "static_analyzer" in self.task_results:
            results.append(self.task_results["static_analyzer"])

        # Add fuzzing result if it exists
        if "fuzzer" in self.task_results:
            results.append(self.task_results["fuzzer"])

        combined_findings: List[Finding] = []
        result_index = 0

        detector_updates = {}
        findings_by_detector = {}

        # Handle context scan results
        for _, detector_name in enumerate(self.task_detector_names):
            context_scan_result = results[result_index]
            result_index += 1

            if isinstance(context_scan_result, (Exception, asyncio.TimeoutError)):
                detector_updates[detector_name] = False
                logger.error(f"Context scan failed - Detector: {detector_name}")
            else:
                detector_updates[detector_name] = True
                findings = context_scan_result.findings
                findings_by_detector[detector_name] = findings
                combined_findings.extend(findings)
                logger.info(
                    f"Context scan completed successfully - Detector: {detector_name}, "
                    f"Found {len(findings)} issues"
                )

        # Handle static analysis result
        if "static_analyzer" in self.task_results:
            static_result = self.task_results["static_analyzer"]
            if isinstance(static_result, Exception):
                logger.error(f"Static analysis failed: {static_result}")
                detector_updates["static_analyzer"] = False
            else:
                detector_updates["static_analyzer"] = True
                slither_findings = static_result.static_analysis_output.findings
                findings_by_detector["static_analyzer"] = slither_findings
                combined_findings.extend(slither_findings)
                logger.info(
                    f"Static analyzer completed successfully with {len(slither_findings)} findings"
                )

        # Handle fuzzing result
        if "fuzzer" in self.task_results:
            fuzzing_result = self.task_results["fuzzer"]
            if isinstance(fuzzing_result, Exception):
                logger.error(f"Fuzzing failed: {fuzzing_result}")
                detector_updates["fuzzer"] = False
            else:
                detector_updates["fuzzer"] = True
                fuzzing_findings = getattr(fuzzing_result.data, "findings", [])
                findings_by_detector["fuzzer"] = fuzzing_findings
                combined_findings.extend(fuzzing_findings)
                logger.info(f"Fuzzing completed successfully with {len(fuzzing_findings)} findings")

        # Single database update for all detectors
        if self.scan:
            self.scan.detectors.update(detector_updates)
            await self.scan.save()

        # Simplified logging for findings
        logger.info(f"Scan {self.scan_id} completed with {len(combined_findings)} total findings.")

        return {
            "combined_findings": combined_findings,
            "summary_result": self.summary_result,
            "detected_type": self.detected_type,
        }

    async def _cleanup_running_tasks(self):
        """Clean up running tasks and ensure proper resource release."""
        gc.collect()
        cleanup_errors = []

        # Helper function to safely cancel a task
        async def safe_cancel(task, task_name: str):
            if task and not task.done():
                try:
                    task.cancel()
                    await task
                except (asyncio.CancelledError, Exception) as e:
                    cleanup_errors.append(f"{task_name} cleanup error: {str(e)}")
                    logger.error(f"Error during {task_name} cleanup: {str(e)}")

        # Cancel context scan tasks
        for task in self.context_scan_tasks:
            await safe_cancel(task, "context_scan")

        # Cancel static analysis task
        await safe_cancel(self.static_analysis_task, "static_analyzer")

        # Cancel fuzzing task
        await safe_cancel(self.fuzzing_task, "fuzzer")

        # Log any cleanup errors
        if cleanup_errors:
            logger.warning(f"Cleanup completed with {len(cleanup_errors)} errors: {cleanup_errors}")
        else:
            logger.info("All tasks cleaned up successfully")

    async def update_progress(self, detector_name: str, success: bool):
        """Update scan progress when a detector completes."""
        if self.scan:
            self.scan.completed_detectors += 1
            self.scan.detectors[detector_name] = success

            current_progress = PRE_DETECTOR_WEIGHT
            for name, completed in self.scan.detectors.items():
                if completed is not None:
                    weight = self.detector_weights.get(name, 7.5)
                    current_progress += weight

            self.scan.progress = max(self.scan.progress, current_progress)

            await self.scan.save()

    async def _send_error_email_once(self):
        """Send error email only if it hasn't been sent yet"""
        if not self.error_email_sent:
            await send_error_email(self.user_email, self.scan_id)
            self.error_email_sent = True
