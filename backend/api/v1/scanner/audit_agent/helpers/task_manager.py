from typing import Dict, List

from api.v1.scanner.audit_agent.schema import AuditAgentScanContext
from config.settings import LLM_SCAN_2, LLM_SCAN_3
from core.db.repositories.user import UserRepository
from core.models.user import SubscriptionType
from core.scanners.base_task_manager import BaseTaskManager
from core.schemas.scan_schema import Detectors
from core.utils.errors import UnsupportedOperationError
from core.utils.profiles import Profiles


class AuditAgentTaskManager(BaseTaskManager):
    """AuditAgent-specific task management logic."""

    def __init__(self, context: AuditAgentScanContext):
        super().__init__(context)
        self.user = None
        self.is_free = False
        self.is_pro = False
        self.is_enterprise = False

    async def initialize(self):
        """Async initialization method to load user data."""
        self.user = await UserRepository.get_by_github_id(self.context.user_id)
        self.is_free = self.user.subscription.type == SubscriptionType.FREE
        self.is_pro = self.user.subscription.type == SubscriptionType.PRO
        self.is_enterprise = self.user.subscription.type == SubscriptionType.ENTERPRISE

    @property
    def available_detectors(self) -> Dict[str, bool]:
        """Define available detectors for AuditAgent scan."""
        return {
            Detectors.CONTEXT_SCAN.value: True,
            Detectors.STATIC_ANALYZER.value: True,
            Detectors.FUZZER.value: False,
            Detectors.MULTI_AGENTS.value: self.is_enterprise,
        }

    @property
    def context_scan_models(self) -> List[str]:
        if not isinstance(self.context, AuditAgentScanContext):
            raise UnsupportedOperationError(
                f"Context type {type(self.context).__name__} does not support AuditAgent operations"
            )

        # Remove o1 model for Free users
        if self.is_free:
            return [LLM_SCAN_2, LLM_SCAN_3, LLM_SCAN_3]

        return super().context_scan_models

    @property
    def context_scan_profiles(self) -> List[Profiles]:
        if not isinstance(self.context, AuditAgentScanContext):
            return super().context_scan_profiles

        # Remove 1 few-shots batch for Free users
        if self.is_free:
            return [Profiles.DEFAULT, Profiles.NONE]

        # For AUDIT_AGENT scan type
        return super().context_scan_profiles
