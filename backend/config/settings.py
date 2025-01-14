import os

from dotenv import load_dotenv

load_dotenv()

TITLE = "AuditAgent - APIs"
DESCRIPTION = "API for auditing smart contracts and detecting vulnerabilities"
VERSION = "0.3.0"

ENVIRONMENT = os.getenv("ENVIRONMENT", "development")
FRONTEND_URL: str = os.getenv("FRONTEND_URL")
BASE_URL: str = os.getenv("BASE_URL")
COOKIE_DOMAIN: str = os.getenv("COOKIE_DOMAIN")
ADMIN_API_KEY: str = os.getenv("ADMIN_API_KEY")

##################################################
#                 LLMs CONFIG
##################################################

OPENAI_API_KEY = os.getenv("OPENAI_API_KEY")
ANTHROPIC_API_KEY = os.getenv("ANTHROPIC_API_KEY")
GEMINI_API_KEY = os.getenv("GEMINI_API_KEY")

# Dictionary of supported models
SUPPORTED_MODELS = {
    "openai": [
        "gpt-4o-2024-11-20",  # 128k - 16k context
        "gpt-4o-2024-08-06",  # 128k - 16k context
        "gpt-4o-mini",  # 128k - 16k context
        "o1",  # 200k - 100k context
        "o1-2024-12-17",  # 200k - 100k context
    ],
    "anthropic": [
        "claude-3-5-sonnet-latest",
    ],
    "gemini": [
        "gemini-1.5-pro",
        "gemini-1.5-pro-latest",
        "gemini-exp-1206",
        "gemini-2.0-flash-exp",
    ],
}

# Default LLM models
LLM_UTILITY = os.getenv("LLM_UTILITY", "claude-3-5-sonnet-latest")
LLM_SCAN_1 = os.getenv("LLM_SCAN_1", "o1-2024-12-17")
LLM_SCAN_2 = os.getenv("LLM_SCAN_2", "claude-3-5-sonnet-latest")
LLM_SCAN_3 = os.getenv("LLM_SCAN_3", "gemini-2.0-flash-exp")


# Tokens encoding: "cl100k_base" || "p50k_base"
TOKENS_ENCODING = "cl100k_base"

# Specify the temperature for the LLM - From 0.0 to 1.0
TEMPERATURE = 0.3


##################################################
#                STRIPE PAYMENTS
##################################################

STRIPE_API_KEY = os.getenv("STRIPE_API_KEY")
STRIPE_WEBHOOK_KEY = os.getenv("STRIPE_WEBHOOK_SECRET")
STRIPE_ENTERPRISE_PRICE_ID = os.getenv("STRIPE_ENTERPRISE_PRICE_ID")
STRIPE_PRO_PRICE_ID = os.getenv("STRIPE_PRO_PRICE_ID")

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

GITHUB_API_URL = "https://api.github.com"
GITHUB_CLIENT_ID: str = os.getenv("GITHUB_CLIENT_ID")
GITHUB_CLIENT_SECRET: str = os.getenv("GITHUB_CLIENT_SECRET")
GITHUB_INSTALLATION_URL: str = os.getenv("GITHUB_INSTALLATION_URL")
GITHUB_APP_URL: str = (
    f"https://github.com/login/oauth/authorize?client_id={GITHUB_CLIENT_ID}&scope=user:email"
)

##################################################
#                   SLACK
##################################################

SLACK_TOKEN = os.getenv("SLACK_TOKEN")


##################################################
#                   EMAIL
##################################################

SMTP_SERVER = os.getenv("SMTP_SERVER")
SMTP_PORT = os.getenv("SMTP_PORT", "587")
SMTP_USERNAME = os.getenv("SMTP_USERNAME")
SMTP_PASSWORD = os.getenv("SMTP_PASSWORD")

##################################################
#                   RETRIES
##################################################

MAX_RETRIES = 3
DELAY = 2
