import stripe
from fastapi import APIRouter, Depends, HTTPException
from starlette.responses import JSONResponse

from api.v1.models.user import User
from api.v1.services.auth_service import get_current_user
from common.logger import logger
from config.settings import FRONTEND_URL

router = APIRouter()


@router.post("/create-portal-session")
async def create_portal_session(current_user: User = Depends(get_current_user)):
    """Create a Stripe Customer Portal session for subscription management."""
    try:
        if not current_user.subscription.stripeCustomerId:
            raise HTTPException(status_code=400, detail="No active subscription found")

        # Create a portal session
        session = stripe.billing_portal.Session.create(
            customer=current_user.subscription.stripeCustomerId,
            return_url=f"{FRONTEND_URL}/dashboard",  # Where to return after managing subscription
        )

        return JSONResponse({"url": session.url})

    except stripe.error.StripeError as e:
        logger.error(f"Stripe error creating portal session: {str(e)}")
        raise HTTPException(status_code=400, detail=str(e))
    except Exception as e:
        logger.error(f"Error creating portal session: {str(e)}")
        raise HTTPException(status_code=500, detail="Internal server error")
