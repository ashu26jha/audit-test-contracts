from datetime import datetime, timezone
from enum import Enum
from typing import Optional
from uuid import UUID

from beanie import Document, Indexed
from pydantic import BaseModel, Field


class TransactionType(str, Enum):
    MANUAL_SCAN = "manual_scan"
    CI_CD = "ci_cd"
    REFUND = "refund"
    RENEWAL = "renewal"


class TransactionStatus(str, Enum):
    PENDING = "pending"
    COMPLETED = "completed"
    FAILED = "failed"
    REFUNDED = "refunded"


class TransactionMetadata(BaseModel):
    branch: Optional[str] = None
    commitHash: Optional[str] = None
    trigger: Optional[str] = None
    error: Optional[str] = None


class CreditTransaction(Document):
    userId: str = Indexed()
    scanId: UUID = Indexed()
    repositoryName: str
    amount: int  # -1 for use, +1 for refund
    type: TransactionType
    status: TransactionStatus = TransactionStatus.PENDING
    timestamp: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    metadata: Optional[TransactionMetadata] = None
    subscription_type: str  # Track which subscription type was used
    renewal_period: Optional[datetime] = None  # Track which renewal period this belongs to

    class Settings:
        name = "credit_transactions"
        indexes = [
            [("userId", 1), ("timestamp", -1)],  # For credit history
            [("scanId", 1)],  # For scan-specific queries
        ]
