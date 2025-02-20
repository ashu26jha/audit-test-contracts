from typing import Dict, List

from api.v1.utilities.benchmark.schema import BenchmarkScanContext
from config.settings import LLM_SCAN_1, LLM_SCAN_2, LLM_SCAN_3
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
            "static_analysis": is_full_scan,  # Only run static analysis for full scan
            "fuzzing": False,
        }

    @property
    def context_scan_models(self) -> List[str]:
        if not isinstance(self.context, BenchmarkContext):
            raise UnsupportedOperationError(
                f"Context type {type(self.context).__name__} does not support Benchmark operations"
            )

        if self.context.type_of_scan == TypeOfScan.MODEL:
            return [self.context.model, self.context.model, self.context.model]

        return [LLM_SCAN_1, LLM_SCAN_2, LLM_SCAN_3]

    @property
    def context_scan_profiles(self) -> List[Profiles]:
        if self.context.mode == ModeType.VANILLA:
            return [Profiles.NONE, Profiles.NONE]

        return [Profiles.DEFAULT, Profiles.DEFAULT_2]
