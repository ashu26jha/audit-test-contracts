from abc import ABC, abstractmethod
from typing import Optional, final
from uuid import UUID

from core.db.repositories.scan import ScanRepository
from core.models.scan import ScanResult
from core.models.user import SubscriptionType, User
from core.schemas.scan_schema import BaseScanContext
from core.utils.logger import logger
from core.utils.profiles import Profiles


class BaseScanInitializer(ABC):
    """Base class for all scan initializers with common functionality."""

    def __init__(self, context: BaseScanContext, user: Optional[User] = None):
        self.context = context
        self.user = user
        self.scan_id: UUID = context.scan_id

    @final
    async def initialize(self) -> None:
        """Main initialization flow."""
        try:
            # 1. Validate request for AuditAgent scans
            await self.validate_request()

            # 2. Create initial Scan record
            await self.create_scan_record()

            # 3. Create initial ScanResult record
            await self._create_initial_scan_result(self.context.scan_number)

        except Exception as e:
            logger.exception(f"[{self.context.scan_type.value}] Initialization failed: {str(e)}")
            raise

    @abstractmethod
    async def validate_request(self) -> None:
        """Validate the request for the scan."""
        pass

    @abstractmethod
    async def create_scan_record(self) -> None:
        """Create the initial scan record."""
        pass

    @final
    async def _create_initial_scan_result(self, scan_number: int) -> None:
        """Create and store an initial empty scan result."""
        initial_scan_result = ScanResult(
            scan_id=self.scan_id,
            scan_number=scan_number,
            summary=None,
            info_message=f"{self.context.scan_type.value} in progress",
            type=Profiles.NONE,
            total_findings=0,
            findings=[],
        )
        await ScanRepository.store_scan_result(initial_scan_result)

    @final
    def get_scan_subscription_type(self) -> str:
        # Default to free user in case of None, since subscription is NONE, it's free scan
        if self.user.subscription is None:
            return SubscriptionType.FREE
        # This ensure we put the correct type
        return self.user.subscription.type
