import asyncio
from asyncio import Semaphore
from datetime import datetime
from typing import Any, Dict, List, Optional, TypedDict
from uuid import UUID

from api.v1.models.scan import Scan
from api.v1.schemas.context_scan_schema import Finding
from api.v1.schemas.fuzzer_schema import SetupResult
from api.v1.services import (  # fuzzing_service,
    context_scan_service,
    generate_summary_service,
    scan_history_service,
    static_analyzer_service,
)
from common.logger import logger
from common.profiles import Profiles
from config.settings import LLM_MODEL_BEST, LLM_MODEL_BEST_2


class TaskManager:
    TOTAL_SCAN_TIMEOUT = 900  # 15 minutes for entire scan
    CONTEXT_SCANS_TIMEOUT = 600  # 10 minutes per context scan

    # Progress stage weights
    PRE_DETECTOR_WEIGHT = 15  # Setup, cloning, etc.
    DETECTOR_WEIGHT = 70  # Detectors
    POST_DETECTOR_WEIGHT = 15  # Deduplication, cleanup

    def __init__(
        self,
        scan_id: UUID,
        flattened_contracts: str,
        selected_contracts: List[str],
        setup_result: Optional[SetupResult],
        detected_profile: Profiles,
    ):
        self.scan_id = scan_id
        self.flattened_contracts = flattened_contracts
        self.selected_contracts = selected_contracts
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

        self.max_concurrent_tasks = 3
        self.task_semaphore = Semaphore(self.max_concurrent_tasks)

        self.task_metrics = {
            "started_at": {},
            "completed_at": {},
            "duration": {},
        }

    async def initialize_scan(self):
        # Fetch the scan document to update detectors
        self.scan = await scan_history_service.get_scan(self.scan_id)

        # Initialize detectors
        detectors: Dict[str, Optional[bool]] = {}
        active_detectors = 0

        # Prepare profiles and models
        profiles = [Profiles.DEFAULT, Profiles.DEFAULT_2]
        models = [LLM_MODEL_BEST, LLM_MODEL_BEST_2]

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
            self.scan.progress = self.PRE_DETECTOR_WEIGHT  # Start at 15% after initialization
            await self.scan.save()

    async def start_tasks(self):
        # Start all tasks with overall timeout
        try:
            async with asyncio.timeout(self.TOTAL_SCAN_TIMEOUT):
                await self._execute_tasks()
        except asyncio.TimeoutError:
            logger.error(
                f"Scan {self.scan_id} exceeded maximum time of {self.TOTAL_SCANS_TIMEOUT}s"
            )
            # Handle timeout - mark remaining tasks as failed

    async def _execute_tasks(self):
        try:
            # Start summary generation task
            self.summary_task = asyncio.create_task(
                generate_summary_service.generate_summary(self.flattened_contracts)
            )

            # Start static analysis task if setup_result is available
            if self.setup_result:
                self.static_analysis_task = asyncio.create_task(
                    static_analyzer_service.run_static_analyzer(
                        "",
                        "",
                        self.selected_contracts,
                        self.setup_result,
                    )
                )
                # Uncomment when fuzzing is ready
                # self.fuzzing_task = asyncio.create_task(
                #     fuzzing_service.run_fuzzer(
                #         "",
                #         "",
                #         self.selected_contracts,
                #         self.flattened_contracts,
                #         self.setup_result,
                #     )
                # )

            # Await summary result to proceed with context scans
            try:
                self.summary_result, self.detected_type = await self.summary_task
            except Exception as e:
                logger.exception(f"Summary generation failed: {str(e)}")
                self.summary_result = "Summary generation failed."
                self.detected_type = Profiles.NONE

            # Start context scan tasks
            await self.start_context_scan_tasks()

        except asyncio.TimeoutError:
            await self._cleanup_running_tasks()
            if self.scan:
                self.scan.status = "failed"
                self.scan.info_message = f"Scan timed out after {self.TOTAL_SCAN_TIMEOUT}s"
                await self.scan.save()
            raise

    async def start_context_scan_tasks(self):
        for config in self.context_scan_configs:
            detector_name = config["detector_name"]
            self.task_metrics["started_at"][detector_name] = datetime.now()
            async with self.task_semaphore:
                await asyncio.sleep(1)
                # Individual context scan timeout
                task = asyncio.create_task(
                    asyncio.wait_for(
                        self.run_context_scan_with_retry(config), timeout=self.CONTEXT_SCANS_TIMEOUT
                    )
                )
                self.context_scan_tasks.append(task)
                self.task_detector_names.append(detector_name)

    async def run_context_scan_with_retry(self, config):
        start_time = datetime.now()
        retry_count = 0
        max_retries = 2  # Limit retries for context scans

        while retry_count < max_retries:
            try:
                # Check remaining time for this context scan
                elapsed = (datetime.now() - start_time).total_seconds()
                if elapsed >= self.CONTEXT_SCANS_TIMEOUT:
                    raise TimeoutError("Context scan exceeded maximum time")

                return await context_scan_service.perform_context_scan(
                    self.summary_result,
                    self.flattened_contracts,
                    config["profile"],
                    config["model"],
                )
            except Exception as e:
                retry_count += 1
                if retry_count >= max_retries:
                    raise
                logger.warning(
                    f"Context scan attempt {retry_count} failed - "
                    f"Profile: {config['profile']}, Model: {config['model']}, "
                    f"Error: {str(e)}"
                )
                # Shorter backoff for context scans
                await asyncio.sleep(5 * retry_count)

    class GatherResults(TypedDict):
        combined_findings: List[Finding]
        summary_result: str
        detected_type: Profiles

    async def gather_results(self) -> GatherResults:
        # Gather tasks to await
        tasks_to_await = self.context_scan_tasks
        if self.static_analysis_task:
            tasks_to_await.append(self.static_analysis_task)
        if self.fuzzing_task:
            tasks_to_await.append(self.fuzzing_task)

        # Use asyncio.gather with return_exceptions=True to handle timeouts
        results = await asyncio.gather(*tasks_to_await, return_exceptions=True)

        combined_findings: List[Finding] = []
        result_index = 0

        # Batch detector updates instead of individual saves
        detector_updates = {}
        findings_by_detector = {}

        # Handle context scan results
        for idx, detector_name in enumerate(self.task_detector_names):
            context_scan_result = results[result_index]
            result_index += 1

            if isinstance(context_scan_result, (Exception, asyncio.TimeoutError)):
                detector_updates[detector_name] = False
                logger.error(f"Context scan failed - Detector: {detector_name}")
                await self.update_progress(detector_name, False)
            else:
                detector_updates[detector_name] = True
                findings = context_scan_result.findings
                findings_by_detector[detector_name] = findings
                combined_findings.extend(findings)
                await self.update_progress(detector_name, True)
                logger.info(
                    f"Context scan completed successfully - Detector: {detector_name}, "
                    f"Found {len(findings)} issues"
                )

        # Handle static analysis result
        if self.static_analysis_task:
            static_result = results[result_index]
            result_index += 1
            if isinstance(static_result, Exception):
                logger.error(f"Static analysis failed: {static_result}")
                detector_updates["static_analyzer"] = False
                await self.update_progress("static_analyzer", False)
            else:
                detector_updates["static_analyzer"] = True
                slither_findings = static_result.slither_output.findings
                findings_by_detector["static_analyzer"] = slither_findings
                combined_findings.extend(slither_findings)
                await self.update_progress("static_analyzer", True)
                logger.info(
                    f"Static analyzer completed successfully with {len(slither_findings)} findings"
                )

        # Handle fuzzing result
        if self.fuzzing_task:
            fuzzing_result = results[result_index]
            if isinstance(fuzzing_result, Exception):
                logger.error(f"Fuzzing failed: {fuzzing_result}")
                detector_updates["fuzzer"] = False
                await self.update_progress("fuzzer", False)
            else:
                detector_updates["fuzzer"] = True
                fuzzing_findings = getattr(fuzzing_result.data, "findings", [])
                findings_by_detector["fuzzer"] = fuzzing_findings
                combined_findings.extend(fuzzing_findings)
                await self.update_progress("fuzzer", True)
                logger.info(f"Fuzzing completed successfully with {len(fuzzing_findings)} findings")

        # Single database update for all detectors
        if self.scan:
            self.scan.detectors.update(detector_updates)
            await self.scan.save()

        # Log summary of all findings before deduplication
        logger.info("=== Findings Summary Before Deduplication ===")
        logger.info(f"Total combined findings: {len(combined_findings)}")
        for detector, findings in findings_by_detector.items():
            logger.info(f"- {detector}: {len(findings)} findings")
        logger.info("==========================================")

        return {
            "combined_findings": combined_findings,
            "summary_result": self.summary_result,
            "detected_type": self.detected_type,
        }

    async def _cleanup_running_tasks(self):
        """Clean up running tasks on timeout."""
        for task in self.context_scan_tasks:
            if not task.done():
                task.cancel()
        if self.static_analysis_task and not self.static_analysis_task.done():
            self.static_analysis_task.cancel()
        if self.fuzzing_task and not self.fuzzing_task.done():
            self.fuzzing_task.cancel()

    async def update_progress(self, detector_name: str, success: bool):
        """Update scan progress when a detector completes."""
        if self.scan:
            self.scan.completed_detectors += 1
            # Calculate detector portion of progress (15-85%)
            detector_progress = (
                self.scan.completed_detectors / self.scan.total_detectors
            ) * self.DETECTOR_WEIGHT
            self.scan.progress = self.PRE_DETECTOR_WEIGHT + detector_progress

            # Update detector status separately
            self.scan.detectors[detector_name] = success

            logger.info(
                f"Progress update: {self.scan.progress:.1f}% "
                f"({self.scan.completed_detectors}/{self.scan.total_detectors} detectors) - "
                f"Detector {detector_name}: {'succeeded' if success else 'failed'}"
            )

            await self.scan.save()
