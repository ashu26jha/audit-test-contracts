from datetime import datetime, timezone
from enum import Enum
from typing import Optional
from uuid import UUID

from beanie import Document, Indexed
from pydantic import BaseModel, ConfigDict, Field, field_validator

from core.utils.ensure_utc import ensure_utc_datetime


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

    model_config = ConfigDict(
        from_attributes=True,
        json_schema_extra={
            "example": {
                "userId": "12345678",
                "scanId": "507f1f77-bcf8-6cd7-9943-901234567890",
                "repositoryName": "smart-contract-repo",
                "amount": -1,
                "type": "manual_scan",
                "status": "completed",
                "timestamp": "2023-10-01T12:00:00Z",
                "metadata": {
                    "branch": "main",
                    "commitHash": "1234567890abcdef",
                    "trigger": "manual",
                    "error": None,
                },
                "subscription_type": "pro",
                "renewal_period": "2023-10-01T00:00:01Z",
            }
        },
    )

    @field_validator("timestamp", "renewal_period", mode="before")
    @classmethod
    def ensure_utc(cls, v):
        return ensure_utc_datetime(v)

    class Settings:
        name = "credit_transactions"
        indexes = [
            [("userId", 1), ("timestamp", -1)],
            [("scanId", 1)],
        ]
