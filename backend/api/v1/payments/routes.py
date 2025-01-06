from typing import Union

from fastapi import APIRouter, Depends, HTTPException, Request

from api.v1.auth.helpers.dependencies import get_current_user
from api.v1.payments.schema import (
    PaymentCheckoutRequest,
    PaymentCheckoutResponse,
    PortalSessionResponse,
)
from core.models.user import User
from core.schemas.api_response_schema import ErrorResponse, SuccessResponse

from .service import StripeSessionService, StripeSubscriptionService, StripeWebhookService

router = APIRouter(prefix="/payments", tags=["payments"])


# Stripe Session
@router.post(
    "/create-stripe-session",
    response_model=Union[SuccessResponse[PaymentCheckoutResponse], ErrorResponse],
    description="Create a checkout session for one-time payment.",
)
async def create_checkout_session(
    request: PaymentCheckoutRequest,
    current_user: User = Depends(get_current_user),
):
    """
    Create a checkout session for one-time payment.

    Returns:
        session_id (str): The ID of the checkout session
        url (str): The URL of the checkout session
    """
    checkout_session = await StripeSessionService.create_checkout_session(
        current_user,
        scan_id=request.scanId,
    )
    return SuccessResponse(
        data=PaymentCheckoutResponse(session_id=checkout_session.id, url=checkout_session.url)
    )


# Stripe Subscription
@router.post(
    "/create-subscription-session",
    response_model=Union[SuccessResponse[PaymentCheckoutResponse], ErrorResponse],
    description="Create a new pro subscription.",
)
async def create_subscription(
    request: PaymentCheckoutRequest, current_user: User = Depends(get_current_user)
):
    """
    Create a new pro subscription.

    Returns:
        session_id (str): The ID of the checkout session
        url (str): The URL of the checkout session
    """
    if current_user.subscription.isActive:
        raise HTTPException(status_code=400, detail="Already have an active subscription")

    session = await StripeSubscriptionService.create_subscription_session(
        current_user,
        scan_id=request.scanId or None,
    )
    return SuccessResponse(data=PaymentCheckoutResponse(session_id=session.id, url=session.url))


# Stripe Webhook
@router.post("/stripe-webhook")
async def stripe_webhook(request: Request):
    """Handle Stripe webhook events."""
    payload = await request.body()
    sig_header = request.headers.get("stripe-signature")

    if not sig_header:
        raise HTTPException(status_code=400, detail="No signature header")

    event = await StripeWebhookService.handle_webhook(payload, sig_header)
    return SuccessResponse(data={"event_type": event["type"]})


# Stripe Portal
@router.post(
    "/create-portal-session",
    response_model=Union[SuccessResponse[PortalSessionResponse], ErrorResponse],
    description="Create a Stripe Customer Portal session for subscription management.",
)
async def create_portal_session(current_user: User = Depends(get_current_user)):
    """
    Create a Stripe Customer Portal session for subscription management.

    Returns:
        url (str): The URL of the Stripe Customer Portal
    """
    session = await StripeSubscriptionService.create_portal_session(current_user)
    return SuccessResponse(data=PortalSessionResponse(url=session.url))
