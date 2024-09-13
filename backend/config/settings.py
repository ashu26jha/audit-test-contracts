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
LLM_MODEL = "gpt-4o-mini-2024-07-18"

# Specify the temperature for the LLM - From 0.0 to 1.0
TEMPERATURE = 0.3
