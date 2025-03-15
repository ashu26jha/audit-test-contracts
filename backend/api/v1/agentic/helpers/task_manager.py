from typing import Dict

from api.v1.agentic.schema import AgenticScanContext
from core.scanners.base_task_manager import BaseTaskManager
from core.schemas.scan_schema import Detectors


class AgenticTaskManager(BaseTaskManager):
    """Agentic-specific task management logic."""

    def __init__(self, context: AgenticScanContext):
        super().__init__(context)

    @property
    def available_detectors(self) -> Dict[str, bool]:
        """Define available detectors for Agentic scan."""
        return {
            Detectors.CONTEXT_SCAN.value: True,
            Detectors.STATIC_ANALYZER.value: False,
            Detectors.FUZZER.value: False,
            Detectors.MULTI_AGENTS.value: False,
        }
