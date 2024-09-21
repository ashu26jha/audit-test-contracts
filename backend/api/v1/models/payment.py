from datetime import datetime, timezone
from uuid import UUID

from beanie import Document, Indexed
from pydantic import Field


class Payment(Document):
    event_id: str = Indexed()
    user_id: str = Indexed()
    scan_id: UUID = Indexed()
    amount: float
    currency: str
    status: str
    stripeSessionId: str
    createdAt: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    updatedAt: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))

    class Settings:
        name = "payments"

    class Config:
        orm_mode = True
        schema_extra = {
            "example": {
                "payment_id": "1f3a5e7c-b2c6-4d8a-9f0e-7d31b9f87e26",
                "user_id": "612e3a5e630d2b1a6f20fb4b",
                "scan_id": "0e4e9e7c-d3a6-4f7a-9b6e-8d57b9f87e26",
                "amount": 120,
                "currency": "USD",
                "status": "pending",
                "stripeSessionId": "cs_test_a1b2c3d4e5f6g7h8i9j0",
                "createdAt": "2023-10-01T12:00:00Z",
                "updatedAt": "2023-10-01T12:00:00Z",
            }
        }
