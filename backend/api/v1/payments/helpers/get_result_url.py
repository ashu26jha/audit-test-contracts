from config.settings import FRONTEND_URL

PAYMENT_RESULT_BASE_URL = f"{FRONTEND_URL}/payment-result"
PAYMENT_RESULT_URL = (
    f"{PAYMENT_RESULT_BASE_URL}?session_id={{CHECKOUT_SESSION_ID}}&status={{status}}"
)


def get_payment_urls() -> tuple[str, str]:
    """Helper method to generate success and cancel URLs."""
    success_url = PAYMENT_RESULT_URL.format(
        CHECKOUT_SESSION_ID="{CHECKOUT_SESSION_ID}", status="success"
    )
    cancel_url = PAYMENT_RESULT_URL.format(
        CHECKOUT_SESSION_ID="{CHECKOUT_SESSION_ID}", status="error"
    )
    return success_url, cancel_url
