from datetime import datetime
from typing import Optional
from uuid import UUID

from pydantic import BaseModel

from api.v1.models.credit_transaction import TransactionStatus, TransactionType


class TransactionMetadataResponse(BaseModel):
    branch: Optional[str] = None
    commitHash: Optional[str] = None
    trigger: Optional[str] = None
    error: Optional[str] = None


class CreditTransactionResponse(BaseModel):
    userId: str
    scanId: UUID
    repositoryName: str
    amount: int
    type: TransactionType
    status: TransactionStatus
    timestamp: datetime
    metadata: Optional[TransactionMetadataResponse] = None
