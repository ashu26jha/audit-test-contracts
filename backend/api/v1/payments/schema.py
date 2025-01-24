from typing import Optional

from pydantic import BaseModel, Field

from core.models.user import SubscriptionType


class SubscriptionCheckoutRequest(BaseModel):
    """Request model for creating a checkout session."""

    scanId: Optional[str] = Field(None, description="Scan ID to make payment for")
    subscription_type: SubscriptionType = Field(..., description="Subscription type")


class SubscriptionCheckoutResponse(BaseModel):
    """Response model for checkout session creation."""

    session_id: str = Field(..., description="Session ID for the checkout")
    url: str = Field(..., description="URL to be redirected at")


class PortalSessionResponse(BaseModel):
    """Response model for portal session creation."""

    url: str


class EnterpriseSubscriptionRequest(BaseModel):
    """Request model for creating an enterprise subscription."""

    email: Optional[str] = Field(None, description="Email address of the user")
    github_id: Optional[str] = Field(None, description="GitHub ID of the user")

    def model_post_init(self, *args, **kwargs):
        super().model_post_init(*args, **kwargs)
        if not self.email and not self.github_id:
            raise ValueError("Either email or github_id must be provided")
