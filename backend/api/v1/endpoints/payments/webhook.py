from api.v1.schemas.api_response_schema import SuccessResponse
from api.v1.services.payment_service import PaymentService
from fastapi import APIRouter, HTTPException, Request

router = APIRouter()


@router.post("/webhook", response_model=SuccessResponse)
async def stripe_webhook(request: Request):
    payload = await request.body()
    sig_header = request.headers.get("stripe-signature")

    try:
        await PaymentService.handle_webhook(payload, sig_header)
        return SuccessResponse(data={"success": True})
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e)) from e
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e)) from e
