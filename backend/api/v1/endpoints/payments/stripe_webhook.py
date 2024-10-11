from fastapi import APIRouter, HTTPException, Request

from api.v1.schemas.api_response_schema import SuccessResponse
from api.v1.services.payments.stripe_webhook_service import StripeWebhookService
from common import logger

router = APIRouter()


@router.post("/stripe-webhook", response_model=SuccessResponse)
async def stripe_webhook(request: Request):
    payload = await request.body()
    sig_header = request.headers.get("stripe-signature")

    try:
        event = await StripeWebhookService.handle_webhook(payload, sig_header)

        # Update payment status in DB
        if (
            event["type"] == "invoice.payment_succeeded"
            or event["type"] == "checkout.session.completed"
        ):
            await StripeWebhookService.update_payment_status(event)

        return SuccessResponse(data="Webhook processed successfully")
    except ValueError as e:
        logger.error(f"Invalid webhook payload: {str(e)}")
        raise HTTPException(status_code=400, detail=str(e)) from e
    except Exception as e:
        logger.error(f"Error processing webhook: {str(e)}")
        raise HTTPException(status_code=500, detail="Internal server error") from e
