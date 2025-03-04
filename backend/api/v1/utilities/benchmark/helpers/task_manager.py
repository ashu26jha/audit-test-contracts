from typing import Dict, List

from api.v1.utilities.benchmark.schema import BenchmarkScanContext
from core.scanners.base_task_manager import BaseTaskManager
from core.schemas.context_protocols import BenchmarkContext
from core.schemas.scan_schema import ModeType, TypeOfScan
from core.utils.errors import UnsupportedOperationError
from core.utils.profiles import Profiles


class BenchmarkTaskManager(BaseTaskManager):
    """Benchmark-specific task management logic."""

    def __init__(self, context: BenchmarkScanContext):
        super().__init__(context)

    @property
    def available_detectors(self) -> Dict[str, bool]:
        """Define available detectors for Benchmark scan."""
        if not isinstance(self.context, BenchmarkContext):
            raise UnsupportedOperationError(
                f"Context type {type(self.context).__name__} does not support Benchmark operations"
            )

        is_full_scan = self.context.type_of_scan == TypeOfScan.AUDIT_AGENT

        return {
            "context_scan": True,
            "static_analyzer": is_full_scan,  # Only run static analyzer for full scan
            "fuzzer": False,
            "multi_agents": False,  # Only run multi-agents for full scan
        }

    @property
    def context_scan_models(self) -> List[str]:
        if not isinstance(self.context, BenchmarkContext):
            raise UnsupportedOperationError(
                f"Context type {type(self.context).__name__} does not support Benchmark operations"
            )

        # For MODEL scan type
        if self.context.type_of_scan == TypeOfScan.MODEL:
            if self.context.mode == ModeType.VANILLA:
                return [self.context.model, self.context.model]  # 2 models for VANILLA
            else:
                return [self.context.model]  # 1 model for FEW_SHOTS

        # For AUDIT_AGENT scan type
        return super().context_scan_models

    @property
    def context_scan_profiles(self) -> List[Profiles]:
        if not isinstance(self.context, BenchmarkContext):
            return super().context_scan_profiles

        # For MODEL scan type
        if self.context.type_of_scan == TypeOfScan.MODEL:
            if self.context.mode == ModeType.VANILLA:
                return [Profiles.NONE]  # 1 profile for VANILLA mode

        # For AUDIT_AGENT scan type
        return super().context_scan_profiles

    @property
    def context_scan_batch_size(self) -> int:
        """
        Customize batch size based on scan type.
        For model benchmarking, use smaller batches to avoid rate limits.
        """
        if not isinstance(self.context, BenchmarkContext):
            return super().context_scan_batch_size

        # For model benchmarking, use batch size of 2
        if self.context.type_of_scan == TypeOfScan.MODEL:
            return 2  # Run identical configurations in the same batch

        # For full scans, use standard batch size
        return super().context_scan_batch_size
