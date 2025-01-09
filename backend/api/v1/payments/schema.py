from typing import Optional

from pydantic import BaseModel, Field

from core.models.user import SubscriptionType


class SubscriptionCheckoutRequest(BaseModel):
    """Request model for creating a checkout session."""

    scanId: Optional[str] = Field(None, description="Scan ID to make payment for")
    subscription_type: SubscriptionType = Field(
        SubscriptionType.PRO, description="Subscription type"
    )


class SubscriptionCheckoutResponse(BaseModel):
    """Response model for checkout session creation."""

    session_id: str = Field(..., description="Session ID for the checkout")
    url: str = Field(..., description="URL to be redirected at")


class PortalSessionResponse(BaseModel):
    """Response model for portal session creation."""

    url: str
