from __future__ import annotations

import anthropic
import openai
from common import logger
from config.settings import ANTHROPIC_API_KEY, OPENAI_API_KEY
from fastapi import HTTPException

# Check for required API keys
if not OPENAI_API_KEY:
    logger.error("Missing OPENAI_API_KEY in environment variables")
    raise HTTPException(status_code=500, detail="Internal Server Error")

if not ANTHROPIC_API_KEY:
    logger.error("Missing ANTHROPIC_API_KEY in environment variables")
    raise HTTPException(status_code=500, detail="Internal Server Error")

# Set up LLM clients
openai.api_key = OPENAI_API_KEY
OPENAI_CLIENT = openai

CLAUDE_CLIENT = anthropic.Anthropic(api_key=ANTHROPIC_API_KEY)
