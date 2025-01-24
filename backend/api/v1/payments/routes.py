from typing import Union

from fastapi import APIRouter, Depends, HTTPException, Request

from api.v1.auth.helpers.dependencies import get_api_key, get_current_user
from api.v1.payments.schema import (
    EnterpriseSubscriptionRequest,
    PortalSessionResponse,
    SubscriptionCheckoutRequest,
    SubscriptionCheckoutResponse,
)
from core.models.user import User
from core.schemas.api_response_schema import ErrorResponse, SuccessResponse

from .service import StripeSubscriptionService, StripeWebhookService

router = APIRouter(prefix="/payments", tags=["payments"])


# Stripe Subscription
@router.post(
    "/create-subscription-session",
    response_model=Union[SuccessResponse[SubscriptionCheckoutResponse], ErrorResponse],
    description="Create a new pro subscription.",
)
async def create_subscription(
    request: SubscriptionCheckoutRequest, current_user: User = Depends(get_current_user)
):
    """
    Create a new subscription.

    Returns:
        session_id (str): The ID of the checkout session
        url (str): The URL of the checkout session
    """
    if (
        current_user.subscription.isActive
        and current_user.subscription.type == request.subscription_type
    ):
        raise HTTPException(status_code=400, detail="Subscription plan already active")

    session = await StripeSubscriptionService.create_subscription_session(
        current_user,
        scan_id=request.scanId or None,
        subscription_type=request.subscription_type,
    )
    return SuccessResponse(
        data=SubscriptionCheckoutResponse(session_id=session.id, url=session.url)
    )


@router.post(
    "/create-enterprise-subscription",
    dependencies=[Depends(get_api_key)],
    response_model=Union[SuccessResponse[SubscriptionCheckoutResponse], ErrorResponse],
    description="Create a new enterprise subscription without payment method.",
)
async def create_enterprise_subscription(request: EnterpriseSubscriptionRequest):
    """
    Create a new enterprise subscription without requiring payment method.

    Args:
        request: Contains either email or github_id of the user

    Returns:
        session_id (str): The ID of the checkout session
        url (str): The URL of the checkout session
    """
    session = await StripeSubscriptionService.create_enterprise_subscription_session(
        email=request.email,
        github_id=request.github_id,
    )
    return SuccessResponse(
        data=SubscriptionCheckoutResponse(session_id=session.id, url=session.url)
    )


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
