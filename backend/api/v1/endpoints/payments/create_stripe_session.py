from fastapi import APIRouter, Depends, HTTPException

from api.v1.models.user import User
from api.v1.schemas.api_response_schema import SuccessResponse
from api.v1.schemas.payments_schema import PaymentCheckoutRequest, PaymentResponse
from api.v1.services.auth_service import get_current_user
from api.v1.services.payments.stripe_session_service import StripeSessionService

router = APIRouter()


@router.post("/create-stripe-session", response_model=SuccessResponse)
async def create_checkout_session(
    request: PaymentCheckoutRequest,
    current_user: User = Depends(get_current_user),
):
    try:
        # Create a checkout session
        checkout_session = await StripeSessionService.create_checkout_session(
            current_user,
            scan_id=request.scanId,
        )

        return SuccessResponse(
            data=PaymentResponse(session_id=checkout_session.id, url=checkout_session.url)
        )
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e)) from e
    except Exception as e:
        raise HTTPException(status_code=500, detail="Internal Server Error") from e
