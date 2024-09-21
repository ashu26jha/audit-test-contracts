from api.v1.services.payment_service import PaymentService
from fastapi import APIRouter, HTTPException, Request

router = APIRouter()


@router.post("/webhook")
async def stripe_webhook(request: Request):
    payload = await request.body()
    sig_header = request.headers.get("stripe-signature")

    try:
        await PaymentService.handle_webhook(payload, sig_header)
        return {"success": True}
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))
