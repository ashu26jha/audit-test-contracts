import os
from dotenv import load_dotenv

load_dotenv()

MONGODB_URL = os.getenv("MONGODB_URL", "mongodb://localhost:27017")
API_KEY = os.getenv("API_KEY")

# LLM API KEYS
OPENAI_API_KEY = os.getenv("OPENAI_API_KEY")
ANTHROPIC_API_KEY = os.getenv("ANTHROPIC_API_KEY")

# Tokens encoding: "cl100k_base" || "p50k_base"
TOKENS_ENCODING = "cl100k_base"

# gpt-4o-2024-08-06 || gpt-4o-mini-2024-07-18 || claude-3-5-sonnet-20240620 || claude-3-opus-20240229
LLM_MODEL = "claude-3-5-sonnet-20240620"

# Specify the temperature for the LLM - From 0.0 to 1.0
TEMPERATURE = 0.3

SUPPORTED_OPENAI_MODELS = ["gpt-4o", "gpt-4o-mini", "gpt-4o-mini-2024-07-18", "o1-preview", "o1-mini" ]