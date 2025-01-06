# pylint: disable=too-many-ancestors,too-few-public-methods

from datetime import datetime, timezone
from enum import Enum
from uuid import UUID

from beanie import Document, Indexed
from pydantic import ConfigDict, Field


class PaymentStatus(str, Enum):
    PENDING = "pending"
    COMPLETED = "completed"
    FAILED = "failed"


class PaymentType(str, Enum):
    ONE_TIME = "one_time"  # Regular single scan payment
    SUBSCRIPTION = "subscription"  # Payment from subscription
    FREE = "free"  # Free scan (0-1 findings)
    FAILED = "failed"  # Failed scan


class Payment(Document):
    event_id: str = Indexed()
    user_id: str = Indexed()
    scan_id: UUID = Indexed()
    amount: float
    currency: str
    status: PaymentStatus = Field(default=PaymentStatus.PENDING)
    stripeSessionId: str = Indexed()
    createdAt: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    updatedAt: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    payment_type: PaymentType = Field(default=PaymentType.ONE_TIME)

    model_config = ConfigDict(
        from_attributes=True,
        json_schema_extra={
            "example": {
                "event_id": "evt_1234567890",
                "user_id": "612e3a5e630d2b1a6f20fb4b",
                "scan_id": "0e4e9e7c-d3a6-4f7a-9b6e-8d57b9f87e26",
                "amount": 120.00,
                "currency": "USD",
                "status": "completed",
                "stripeSessionId": "cs_test_a1b2c3d4e5f6g7h8i9j0",
                "createdAt": "2023-10-01T12:00:00Z",
                "updatedAt": "2023-10-01T12:00:01Z",
                "payment_type": "one_time",
            }
        },
    )

    class Settings:
        name = "payments"
        validate_on_save = True
        indexes = [
            [("scan_id", 1)],  # Scan payment lookup
            [("stripeSessionId", 1)],  # Stripe session lookup
            [("user_id", 1), ("createdAt", -1)],  # User payment history
            [("event_id", 1)],  # Stripe event lookup
        ]
