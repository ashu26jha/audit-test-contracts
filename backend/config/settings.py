import os

from dotenv import load_dotenv

load_dotenv()

ENVIRONMENT = os.getenv("ENVIRONMENT", "development")
FRONTEND_URL: str = os.getenv("FRONTEND_URL")
BASE_URL: str = os.getenv("BASE_URL")
ADMIN_API_KEY: str = os.getenv("ADMIN_API_KEY")

##################################################
#                 LLMs CONFIG
##################################################

OPENAI_API_KEY = os.getenv("OPENAI_API_KEY")
ANTHROPIC_API_KEY = os.getenv("ANTHROPIC_API_KEY")

# Dictionary of supported models
SUPPORTED_MODELS = {
    "openai": [
        "gpt-4o-2024-08-06",  # 128k - 16k context
        "gpt-4o-mini",  # 128k - 16k context
        "o1-preview",  # 128k - 32k context
        "o1-mini",  # 128k - 65k context
    ],
    "anthropic": [
        "claude-3-5-sonnet-20240620",
    ],
}

# Default LLM models
LLM_MODEL_CHEAP = os.getenv("LLM_MODEL_CHEAP", "gpt-4o-mini")
LLM_MODEL_MEDIUM = os.getenv("LLM_MODEL_MEDIUM", "gpt-4o-2024-08-06")
LLM_MODEL_BEST = os.getenv("LLM_MODEL_BEST", "o1-preview")

# List of models that do not support 'system' role
MODELS_NOT_SUPPORTING_SYSTEM = ["o1-preview", "o1-mini"]

# Tokens encoding: "cl100k_base" || "p50k_base"
TOKENS_ENCODING = "cl100k_base"

# Specify the temperature for the LLM - From 0.0 to 1.0
TEMPERATURE = 0.3


##################################################
#                STRIPE PAYMENTS
##################################################

STRIPE_API_KEY = os.getenv("STRIPE_API_KEY")
STRIPE_WEBHOOK_KEY = os.getenv("STRIPE_WEBHOOK_SECRET")
VOUCHER_CODE = os.getenv("VOUCHER_CODE")

##################################################
#                   MONGODB
##################################################

MONGODB_URL: str = os.getenv("MONGODB_URL")
SECRET_KEY: str = os.getenv("SECRET_KEY")
if not SECRET_KEY:
    raise ValueError("SECRET_KEY environment variable is not set.")
ALGORITHM: str = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES: int = 10800  # 1 week


##################################################
#                   GITHUB
##################################################

GITHUB_CLIENT_ID: str = os.getenv("GITHUB_CLIENT_ID")
GITHUB_CLIENT_SECRET: str = os.getenv("GITHUB_CLIENT_SECRET")


##################################################
#                   EMAIL
##################################################

SMTP_SERVER = os.getenv("SMTP_SERVER")
SMTP_PORT = os.getenv("SMTP_PORT", 587)
SMTP_USERNAME = os.getenv("SMTP_USERNAME")
SMTP_PASSWORD = os.getenv("SMTP_PASSWORD")
CC_EMAIL = os.getenv("CC_EMAIL")

##################################################
#                   REDIS
##################################################

REDIS_URL: str = os.getenv("REDIS_URL", "redis://localhost:6379")

##################################################
#                   RETRIES
##################################################

MAX_RETRIES = 3
DELAY = 2
