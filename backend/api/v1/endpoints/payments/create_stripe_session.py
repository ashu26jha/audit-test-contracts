from api.v1.schemas.api_response_schema import SuccessResponse
from api.v1.schemas.payments_schema import PaymentCheckoutRequest, PaymentResponse
from api.v1.services.payments.stripe_session_service import StripeSessionService
from fastapi import APIRouter, HTTPException

router = APIRouter()


@router.post("/create-stripe-session", response_model=SuccessResponse)
async def create_checkout_session(request: PaymentCheckoutRequest):
    try:
        # Create a checkout session
        checkout_session = await StripeSessionService.create_checkout_session(
            scan_id=request.scanId
        )

        return SuccessResponse(
            data=PaymentResponse(session_id=checkout_session.id, URL=checkout_session.url)
        )
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e)) from e
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e)) from e
