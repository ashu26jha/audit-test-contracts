import os

from dotenv import load_dotenv

load_dotenv()


TITLE = "AuditAgent - APIs"
DESCRIPTION = "API for auditing smart contracts and detecting vulnerabilities"
VERSION = "1.1.3"  # Auto-updated by pre-commit hook

ENVIRONMENT = os.getenv("ENVIRONMENT", "development")
FRONTEND_URL: str = os.getenv("FRONTEND_URL")
COOKIE_DOMAIN: str = os.getenv("COOKIE_DOMAIN")
ADMIN_API_KEY: str = os.getenv("ADMIN_API_KEY")
AGENTIC_API_KEY: str = os.getenv("AGENTIC_API_KEY")


##################################################
#                 LLMs CONFIG
##################################################

OPENAI_API_KEY = os.getenv("OPENAI_API_KEY")
ANTHROPIC_API_KEY = os.getenv("ANTHROPIC_API_KEY")
GEMINI_API_KEY = os.getenv("GEMINI_API_KEY")
XAI_API_KEY = os.getenv("XAI_API_KEY")

# Dictionary of supported models
SUPPORTED_MODELS = {
    "openai": [
        "chatgpt-4o-latest",  # 128k - 16k context
        "gpt-4o-2024-11-20",  # 128k - 16k context
        "gpt-4o-2024-08-06",  # 128k - 16k context
        "gpt-4o-mini",  # 128k - 16k context
        "o1",  # 200k - 100k context
        "o1-2024-12-17",  # 200k - 100k context
        "o3-mini",  # 200k - 100k context
    ],
    "anthropic": [
        "claude-3-5-sonnet-latest",
        "claude-3-7-sonnet-20250219",
    ],
    "gemini": [
        "gemini-1.5-pro",
        "gemini-1.5-pro-latest",
        "gemini-exp-1206",
        "gemini-2.0-flash-exp",
        "gemini-2.0-pro-exp",
        "gemini-2.0-flash-thinking-exp-01-21",
    ],
    "grok": [
        "grok-beta",
    ],
}

# Default LLM models
LLM_UTILITY = os.getenv("LLM_UTILITY", "claude-3-7-sonnet-20250219")
LLM_SCAN_1 = os.getenv("LLM_SCAN_1", "o1-2024-12-17")
LLM_SCAN_2 = os.getenv("LLM_SCAN_2", "claude-3-7-sonnet-20250219")
LLM_SCAN_3 = os.getenv("LLM_SCAN_3", "o3-mini")

# Deduplication parameters
DEDUP_MIN_BATCH_SIZE = 12
DEDUP_MAX_BATCHES = 6

# Tokens encoding: "cl100k_base" || "p50k_base"
TOKENS_ENCODING = "cl100k_base"

# Specify the temperature for the LLM - From 0.0 to 1.0
TEMPERATURE = 0
MAX_RETRIES = 3
DELAY = 2


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
#                   EMAIL
##################################################

SMTP_SERVER = os.getenv("SMTP_SERVER")
SMTP_PORT = os.getenv("SMTP_PORT", "587")
SMTP_USERNAME = os.getenv("SMTP_USERNAME")
SMTP_PASSWORD = os.getenv("SMTP_PASSWORD")


##################################################
#                  LANGFUSE
##################################################

LANGFUSE_SECRET_KEY = os.getenv("LANGFUSE_SECRET_KEY")
LANGFUSE_PUBLIC_KEY = os.getenv("LANGFUSE_PUBLIC_KEY")
LANGFUSE_HOST = os.getenv("LANGFUSE_HOST")


##################################################
#                  ETHERSCAN
##################################################

ETHERSCAN_API_KEY = os.getenv("ETHERSCAN_API_KEY")
BASE_ETHERSCAN_URL = "https://api.etherscan.io/v2/api"


##################################################
#               SLACK (Optional)
##################################################

SLACK_TOKEN = os.getenv("SLACK_TOKEN")


##################################################
#         ELIZA (Only for Agentic scans)
##################################################

ELIZA_CALLBACK_URL = os.getenv("ELIZA_CALLBACK_URL")

##################################################
#         JINA (Only for Autonomous Agent)
##################################################

JINA_API_KEY = os.getenv("JINA_API_KEY")

SOLODIT_EMAIL = os.getenv("SOLODIT_EMAIL")
SOLODIT_PASSWORD = os.getenv("SOLODIT_PASSWORD")
