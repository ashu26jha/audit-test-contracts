import asyncio
from typing import Any, Dict, List, Optional, TypedDict

from fastapi import HTTPException
from langfuse.decorators import langfuse_context

from api.v1.agentic.schema import AgenticScanContext
from api.v1.detectors.context_scan.service import run_context_scan_batch
from api.v1.utilities.summary.service import generate_summary
from config.settings import LLM_SCAN_1, LLM_SCAN_2, LLM_SCAN_3
from core.db.repositories.scan import ScanRepository
from core.models.scan import Finding, Scan
from core.utils.logger import logger
from core.utils.process_pool import ProcessPoolManager
from core.utils.profiles import Profiles

TOTAL_SCAN_TIMEOUT = 900  # 15 minutes for entire scan
CONTEXT_SCANS_TIMEOUT = 300  # 10 minutes per context scan


class TaskManager:

    def __init__(
        self,
        context: AgenticScanContext,
    ):
        self.scan_id = context.scan_id
        self.flattened_contracts = context.flattened_contracts
        self.selected_contracts = context.contract_files
        self.scan: Optional[Scan] = None
        self.context_scan_configs: List[Dict[str, Any]] = []
        self.task_detector_names: List[str] = []

        self.task_results = {}  # Store task results
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

        # Save initial detectors to scan
        if self.scan:
            self.scan.detectors = detectors
            self.scan.total_detectors = active_detectors
            self.scan.completed_detectors = 0
            await self.scan.save()

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
                # TODO: Send error email to ELIZA BOT
                raise HTTPException(
                    status_code=500,
                    detail="Internal server error during summary generation.",
                ) from e

            # 3. Context Scans - Strict batching with verification
            await self._run_context_scans_in_batches()

        except asyncio.TimeoutError as e:
            logger.error(f"Scan {self.scan_id} exceeded maximum time of {TOTAL_SCAN_TIMEOUT}s")
            await self._cleanup_running_tasks()
            await ScanRepository.update_scan_failure(self.scan_id, "Scan timed out")
            # TODO: Send error email to ELIZA BOT
            raise HTTPException(
                status_code=500, detail=f"Scan timed out after {TOTAL_SCAN_TIMEOUT}s"
            ) from e
        except Exception as e:
            logger.error(f"Error in task execution: {str(e)}")
            raise

    async def _run_context_scans_in_batches(self):
        """Run context scans in batches, ensuring model distribution."""
        batch_size = 3
        configs = self.context_scan_configs
        total_configs = len(configs)

        # Process configs in pairs of batches
        for i in range(0, total_configs, batch_size * 2):
            # Create two batches of 3 configs each
            batch1 = configs[i : i + batch_size]  # noqa: E203
            batch2 = configs[i + batch_size : i + (batch_size * 2)]  # noqa: E203

            # Process both batches simultaneously
            tasks = []
            for batch_num, batch in enumerate([batch1, batch2], 1):
                if batch:
                    logger.info(
                        f"Starting batch {batch_num} with models: {[c['model'] for c in batch]}"
                    )
                    task = asyncio.create_task(self.run_context_scan_with_batch(batch))
                    tasks.append(task)

            # Wait for all tasks to complete
            await asyncio.gather(*tasks, return_exceptions=True)

    async def run_context_scan_with_batch(self, batch_configs):
        """Run a batch of context scans using process pool"""
        try:
            logger.info(
                f"[ProcessPool] Starting batch scan with models: {[c['model'] for c in batch_configs]}"
            )
            trace_id = langfuse_context.get_current_trace_id()
            response_dicts = await self.process_pool.run_in_process(
                run_context_scan_batch,
                self.flattened_contracts,
                self.summary_result,
                batch_configs,
                trace_id,
            )
            return response_dicts
        except Exception as e:
            logger.error(f"Batch context scan failed: {str(e)}")
            raise

    class GatherResults(TypedDict):
        combined_findings: List[Finding]
        summary_result: str
        detected_type: Profiles

    async def gather_results(self) -> GatherResults:
        # Use stored results instead of awaiting tasks again
        results = []
        detector_name_to_result = {}

        # Gather context scan results and create mapping
        for detector_name in self.task_detector_names:
            result = self.task_results.get(detector_name)
            results.append(result)
            detector_name_to_result[detector_name] = result

        combined_findings: List[Finding] = []
        detector_updates = {}
        findings_by_detector = {}

        # Handle context scan results
        for detector_name in self.task_detector_names:
            context_scan_result = detector_name_to_result[detector_name]

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

        # Log any cleanup errors
        if cleanup_errors:
            logger.warning(f"Cleanup completed with {len(cleanup_errors)} errors: {cleanup_errors}")
        else:
            logger.info("All tasks cleaned up successfully")
