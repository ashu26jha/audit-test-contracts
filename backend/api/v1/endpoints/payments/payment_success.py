from datetime import datetime, timezone
from uuid import UUID

import stripe
from api.v1.models.payment import Payment
from api.v1.models.user import User
from api.v1.schemas.api_response_schema import SuccessResponse
from bson import ObjectId
from fastapi.responses import RedirectResponse
from fastapi import APIRouter, Query, status, HTTPException
from config import settings
from api.v1.services.scan_history_service import update_scan_paid_status
from api.v1.services.payment_service import PaymentService
from api.v1.models.payment import Payment
from api.v1.services.generate_pdf_service import generate_pdf_from_scan
from uuid import UUID
import stripe
from datetime import datetime, timezone

router = APIRouter()


@router.get(
    "/payment_success",
    response_model=SuccessResponse,
    status_code=status.HTTP_201_CREATED,
)
async def payment_success(session_id: str = Query(...)):
    try:
        # Retrieve the session from Stripe
        session = stripe.checkout.Session.retrieve(session_id)

        # Validate the session
        if session.payment_status != 'paid':
            raise ValueError("Payment has not been completed")

        # Optionally, check if the session has expired
        expiry_date = datetime.fromtimestamp(session.expires_at, timezone.utc)
        if expiry_date < datetime.now(timezone.utc):
            raise ValueError("Session has expired")

        # Extract scanId and userId from the session metadata
        scan_id = UUID(session.metadata.get('scanId'))
        user_id = session.metadata.get('userId')

        if not scan_id or not user_id:
            raise ValueError("Missing scanId or userId in session metadata")

        # Check if payment has already been processed
        existing_payment = await Payment.find_one(Payment.stripeSessionId == session_id)
        if existing_payment:
            raise ValueError("Payment has already been processed")

        # Update scan status to paid
        await update_scan_paid_status(scan_id, True)

        # Create a new Payment record
        payment = Payment(
            # Using session_id as a unique identifier
            event_id=f"session_{session_id}",
            user_id=user_id,
            scan_id=scan_id,
            amount=session.amount_total / 100,  # Convert from cents to dollars
            currency=session.currency,
            status="completed",
            stripeSessionId=session_id
        )
        await payment.create()

        # Retrieve the User object
        user = await User.get(ObjectId(user_id))
        if not user:
            raise ValueError(f"No user found with ID: {user_id}")

        # Generate PDF
        await generate_pdf_from_scan(user, scan_id)

        # Redirect to payment results page
        print(
            f"{settings.FRONTEND_URL}/payment-result?session_id={session_id}&status=success")
        redirect_url = f"{settings.FRONTEND_URL}/payment-result?session_id={session_id}&status=success"
        return RedirectResponse(url=redirect_url)

    except stripe.error.StripeError as e:
        print(f"Stripe error: {str(e)}")
        raise HTTPException(
            status_code=400, detail="Error retrieving Stripe session")
    except ValueError as e:
        print(f"Value error: {str(e)}")
        raise HTTPException(status_code=400, detail=str(e))
    except Exception as e:
        print(f"Error in payment_success: {str(e)}")
        redirect_url = f"{settings.FRONTEND_URL}/payment-result?session_id={session_id}&status=error"
        return RedirectResponse(url=redirect_url)
