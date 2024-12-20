from fastapi import APIRouter, Depends, HTTPException

from api.v1.models.user import User
from api.v1.schemas.api_response_schema import SuccessResponse
from api.v1.schemas.payments_schema import PaymentCheckoutRequest, PaymentResponse
from api.v1.services.auth_service import get_current_user
from api.v1.services.payments.stripe_session_service import StripeSessionService

router = APIRouter()


@router.post("/create-subscription-session")
async def create_subscription(
    request: PaymentCheckoutRequest, current_user: User = Depends(get_current_user)
):
    """Create a new pro subscription."""
    if current_user.subscription.isActive:
        raise HTTPException(status_code=400, detail="Already have an active subscription")

    try:
        session = await StripeSessionService.create_subscription_session(
            current_user,
            scan_id=request.scanId or None,
        )
        return SuccessResponse(data=PaymentResponse(session_id=session.id, url=session.url))
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))
