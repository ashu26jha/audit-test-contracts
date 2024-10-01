from api.v1.models.payment import Payment
from api.v1.models.user import User
from api.v1.services.generate_pdf_service import generate_pdf_from_scan
from api.v1.services.payments.stripe_session_service import StripeSessionService
from bson import ObjectId
from common import logger
from fastapi import HTTPException


class PaymentSuccessService:

    @staticmethod
    async def process_successful_payment(session_id: str):
        try:
            payment = await Payment.find_one(Payment.stripeSessionId == session_id)
            if not payment:
                logger.warning(f"Payment not found for session ID: {session_id}")
                raise HTTPException(status_code=400, detail="Invalid session ID")

            session = await StripeSessionService.retrieve_session(session_id)
            logger.info(f"Payment status for session {session_id}: {session.payment_status}")

            if session.payment_status == "paid":
                user = await User.get(ObjectId(payment.user_id))
                if not user:
                    raise ValueError(f"User not found for ID: {payment.user_id}")

                await generate_pdf_from_scan(user, payment.scan_id)
                logger.info(f"PDF generated for session ID: {session_id}")
                return "Payment processed successfully"

        except Exception as e:
            logger.error(f"Error after processing payment: {e}")
            raise HTTPException(status_code=500, detail="Internal server error")
