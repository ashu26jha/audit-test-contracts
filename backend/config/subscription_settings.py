from datetime import timedelta

from config.settings import STRIPE_ENTERPRISE_PRICE_ID, STRIPE_PRO_PRICE_ID
from core.models.user import SubscriptionType

SUBSCRIPTION_SETTINGS = {
    "free": {
        "type": SubscriptionType.FREE,
        "max_contracts": 3,
        "max_loc": 525,  # Add 5% buffer due to frontend mismatch
        "monthly_credits": 0,
        "price": 0,  # $0.00
    },
    "pro": {
        "type": SubscriptionType.PRO,
        "max_contracts": 10,
        "max_loc": 2100,  # Add 5% buffer due to frontend mismatch
        "monthly_credits": 5,
        "credit_expiry_period": timedelta(days=30),
        "price": STRIPE_PRO_PRICE_ID,
    },
    "enterprise": {
        "type": SubscriptionType.ENTERPRISE,
        "max_contracts": 50,
        "max_loc": 8400,  # Add 5% buffer due to frontend mismatch
        "monthly_credits": 10,
        "credit_expiry_period": timedelta(days=30),
        "price": STRIPE_ENTERPRISE_PRICE_ID,
    },
}
