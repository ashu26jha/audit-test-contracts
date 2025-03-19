from typing import Dict, List

from api.v1.scanner.cairo.schema import CairoScanContext
from core.scanners.base_task_manager import BaseTaskManager
from core.utils.profiles import Profiles


class CairoTaskManager(BaseTaskManager):
    """Cairo-specific task management logic."""

    def __init__(self, context: CairoScanContext):
        super().__init__(context)

    @property
    def available_detectors(self) -> Dict[str, bool]:
        """Define available detectors for Cairo scan."""
        return {
            "context_scan": True,
            "static_analyzer": False,
            "fuzzer": False,
            "multi_agents": False,
        }

    @property
    def context_scan_profiles(self) -> List[Profiles]:
        """Define profiles for Cairo scan."""
        return [Profiles.CAIRO, Profiles.CAIRO, Profiles.NONE]
