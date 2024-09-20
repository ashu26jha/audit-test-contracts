import stripe
from api.v1.schemas.payments import PaymentCheckoutRequest, PaymentResponse
from config.settings import STRIPE_API_KEY
from fastapi import APIRouter, HTTPException

router = APIRouter()
stripe.api_key = STRIPE_API_KEY


@router.post("/create-checkout-session", response_model=PaymentResponse)
async def create_checkout_session(request: PaymentCheckoutRequest):

    user_id = "abc"  # To get from database
    try:
        checkout_session = stripe.checkout.Session.create(
            billing_address_collection="auto",
            customer_email="test@nethermind.net",  # Actual email id, Fetch from DB for the user id
            line_items=[
                {
                    "price_data": {
                        "currency": "usd",
                        "product_data": {"name": "Test product"},
                        "unit_amount": 120,
                    },
                    "quantity": 1,  # Can be dynamic too
                }
            ],
            mode="payment",
            success_url="http://0.0.0.0:8000/api/v1/payments/payment_success?session_id={CHECKOUT_SESSION_ID}",  # `success_url` is a required parameter
            metadata={
                "userId": user_id,
                "scanId": request.scanId,
            },
        )
        return PaymentResponse(session_id=checkout_session.id, URL=checkout_session.url)
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))
