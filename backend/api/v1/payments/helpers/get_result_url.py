from config.settings import FRONTEND_URL

PAYMENT_RESULT_BASE_URL = f"{FRONTEND_URL}/payment-result"
PAYMENT_RESULT_URL = (
    f"{PAYMENT_RESULT_BASE_URL}"
    f"?session_id={{CHECKOUT_SESSION_ID}}"
    f"&status={{status}}"
    f"&scan_id={{scan_id}}"
)


def get_payment_urls(scan_id: str) -> tuple[str, str]:
    """Helper method to generate success and cancel URLs."""
    success_url = PAYMENT_RESULT_URL.format(
        CHECKOUT_SESSION_ID="{CHECKOUT_SESSION_ID}", status="success", scan_id=scan_id
    )
    cancel_url = PAYMENT_RESULT_URL.format(
        CHECKOUT_SESSION_ID="{CHECKOUT_SESSION_ID}", status="error", scan_id=scan_id
    )
    return success_url, cancel_url
