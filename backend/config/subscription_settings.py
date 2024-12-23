from datetime import timedelta

from config.settings import STRIPE_SUBSCRIPTION_PRICE_ID

SUBSCRIPTION_SETTINGS = {
    "single": {
        "type": "single",
        "max_contracts": 10,
        "max_loc": 2000,
        "price": 4900,  # $49.00
    },
    "pro": {
        "type": "pro",
        "max_contracts": 40,
        "max_loc": 8000,
        "monthly_credits": 20,
        "credit_expiry_period": timedelta(days=30),
        "price": STRIPE_SUBSCRIPTION_PRICE_ID,
    },
}
