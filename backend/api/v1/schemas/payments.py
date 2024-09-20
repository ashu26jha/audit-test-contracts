from pydantic import BaseModel, Field


class PaymentCheckoutRequest(BaseModel):
    scanId: str = Field(..., description="Scan ID to make payment for")


class PaymentResponse(BaseModel):
    session_id: str = Field(..., description="Session ID for the checkout")
    URL: str = Field(..., description="URL to be redirected at")
