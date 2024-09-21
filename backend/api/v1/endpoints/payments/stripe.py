from api.v1.schemas.api_response_schema import SuccessResponse
from api.v1.schemas.payments import PaymentCheckoutRequest, PaymentResponse
from api.v1.services.payment_service import PaymentService
from fastapi import APIRouter, HTTPException

router = APIRouter()


@router.post("/create-checkout-session", response_model=SuccessResponse)
async def create_checkout_session(request: PaymentCheckoutRequest):
    try:
        checkout_session = await PaymentService.create_checkout_session(scan_id=request.scanId)
        return SuccessResponse(
            data=PaymentResponse(session_id=checkout_session.id, URL=checkout_session.url)
        )
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e)) from e
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e)) from e
