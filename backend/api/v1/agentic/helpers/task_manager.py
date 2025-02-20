from typing import Dict

from api.v1.agentic.schema import AgenticScanContext
from core.scanners.base_task_manager import BaseTaskManager


class AgenticTaskManager(BaseTaskManager):
    """Agentic-specific task management logic."""

    def __init__(self, context: AgenticScanContext):
        super().__init__(context)

    @property
    def available_detectors(self) -> Dict[str, bool]:
        """Define available detectors for Agentic scan."""
        return {
            "context_scan": True,
            "static_analysis": False,
            "fuzzing": False,
        }
