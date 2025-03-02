from typing import Dict

from api.v1.audit_agent.schema import AuditAgentScanContext
from core.scanners.base_task_manager import BaseTaskManager


class AuditAgentTaskManager(BaseTaskManager):
    """AuditAgent-specific task management logic."""

    def __init__(self, context: AuditAgentScanContext):
        super().__init__(context)

    @property
    def available_detectors(self) -> Dict[str, bool]:
        """Define available detectors for Agentic scan."""
        return {
            "context_scan": True,
            "static_analyzer": True,
            "fuzzer": False,
            "multi_agents": False,
        }
