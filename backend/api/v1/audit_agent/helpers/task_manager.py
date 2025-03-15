from typing import Dict

from api.v1.audit_agent.schema import AuditAgentScanContext
from core.scanners.base_task_manager import BaseTaskManager
from core.schemas.scan_schema import Detectors


class AuditAgentTaskManager(BaseTaskManager):
    """AuditAgent-specific task management logic."""

    def __init__(self, context: AuditAgentScanContext):
        super().__init__(context)

    @property
    def available_detectors(self) -> Dict[str, bool]:
        """Define available detectors for AuditAgent scan."""
        return {
            Detectors.CONTEXT_SCAN.value: True,
            Detectors.STATIC_ANALYZER.value: True,
            Detectors.FUZZER.value: False,
            Detectors.MULTI_AGENTS.value: False,
        }
