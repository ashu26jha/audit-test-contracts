from __future__ import annotations

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

# Specify the temperature for the LLM - From 0.0 to 1.0
TEMPERATURE = 0.3

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

# List of models that do not support 'system' role
MODELS_NOT_SUPPORTING_SYSTEM = ["o1-preview", "o1-mini"]

# Default LLM models
LLM_MODEL = "gpt-4o-mini"
LLM_MODEL_SUMMARY = "gpt-4o-mini"
