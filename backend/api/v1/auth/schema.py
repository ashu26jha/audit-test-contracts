from datetime import datetime
from typing import List, Optional

from pydantic import BaseModel, ConfigDict, EmailStr


class UsernameRequest(BaseModel):
    username: str


class SubscriptionData(BaseModel):
    """Response model for subscription data"""

    isActive: bool = False
    type: str = "free"
    credits: int = 0
    monthlyCredits: int = 0
    expiresAt: Optional[datetime] = None
    lastRenewalAt: Optional[datetime] = None
    cancelAtPeriodEnd: Optional[bool] = False

    model_config = ConfigDict(from_attributes=True)


class UserResponse(BaseModel):
    """API response model for user data - excludes sensitive information"""

    username: str
    email: EmailStr
    githubId: str
    avatarUrl: Optional[str] = None
    name: Optional[str] = None
    installationId: Optional[List[int]] = []  # Optional with default empty list
    subscription: SubscriptionData

    model_config = ConfigDict(from_attributes=True)


class TestAuthResponse(BaseModel):
    access_token: str
    token_type: str
    user: UserResponse
