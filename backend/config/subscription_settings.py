from datetime import timedelta

from config.settings import STRIPE_ENTERPRISE_PRICE_ID, STRIPE_PRO_PRICE_ID
from core.models.user import SubscriptionType

SUBSCRIPTION_SETTINGS = {
    "free": {
        "type": SubscriptionType.FREE,
        "max_contracts": 3,
        "max_loc": 510,  # Includes 2% buffer to accommodate possible inconsistencies
        "monthly_credits": 0,
        "price": 0,  # $0.00
    },
    "pro": {
        "type": SubscriptionType.PRO,
        "max_contracts": 10,
        "max_loc": 2040,  # Includes 2% buffer to accommodate possible inconsistencies
        "monthly_credits": 5,
        "credit_expiry_period": timedelta(days=30),
        "price": STRIPE_PRO_PRICE_ID,
    },
    "enterprise": {
        "type": SubscriptionType.ENTERPRISE,
        "max_contracts": 50,
        "max_loc": 8160,  # Includes 2% buffer to accommodate possible inconsistencies
        "monthly_credits": 10,
        "credit_expiry_period": timedelta(days=30),
        "price": STRIPE_ENTERPRISE_PRICE_ID,
    },
}
