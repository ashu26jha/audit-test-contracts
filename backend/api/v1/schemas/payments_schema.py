from typing import Optional

from pydantic import BaseModel, Field


class PaymentCheckoutRequest(BaseModel):
    scanId: Optional[str] = Field(None, description="Scan ID to make payment for")


class PaymentResponse(BaseModel):
    session_id: str = Field(..., description="Session ID for the checkout")
    url: str = Field(..., description="URL to be redirected at")
