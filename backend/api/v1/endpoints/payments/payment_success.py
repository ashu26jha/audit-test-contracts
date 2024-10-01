from api.v1.schemas.api_response_schema import SuccessResponse
from api.v1.services.payments.payment_success_service import PaymentSuccessService
from fastapi import APIRouter, Query

router = APIRouter()


@router.get(
    "/payment-success",
    response_model=SuccessResponse,
)
async def payment_success(session_id: str = Query(...)):
    await PaymentSuccessService.process_successful_payment(session_id)
    return SuccessResponse(data="Payment processed successfully")
