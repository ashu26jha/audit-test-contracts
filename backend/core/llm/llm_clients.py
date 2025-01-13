import google.generativeai as genai
import httpx
import instructor
import openai
from anthropic import AsyncAnthropic
from fastapi import HTTPException

from config.settings import ANTHROPIC_API_KEY, GEMINI_API_KEY, OPENAI_API_KEY
from core.utils.logger import logger

# Check for required API keys
if not OPENAI_API_KEY:
    logger.error("Missing OPENAI_API_KEY in environment variables")
    raise HTTPException(status_code=500, detail="Internal Server Error")

if not ANTHROPIC_API_KEY:
    logger.error("Missing ANTHROPIC_API_KEY in environment variables")
    raise HTTPException(status_code=500, detail="Internal Server Error")

if not GEMINI_API_KEY:
    logger.error("Missing GEMINI_API_KEY in environment variables")
    raise HTTPException(status_code=500, detail="Internal Server Error")


# Getter for OpenAI client
def get_openai_client():
    """Get a configured OpenAI client instance."""
    openai.api_key = OPENAI_API_KEY
    return openai


# Getter for Anthropic client
def get_claude_client():
    """Get a configured Claude client instance with instructor integration."""
    try:
        timeout = httpx.Timeout(300.0, connect=10.0)  # 5 minutes total, 10s connect
        limits = httpx.Limits(max_keepalive_connections=5, max_connections=10)
        http_client = httpx.AsyncClient(timeout=timeout, limits=limits)
        base_claude_client = AsyncAnthropic(
            api_key=ANTHROPIC_API_KEY,
            http_client=http_client,
        )
        claude_client = instructor.from_anthropic(base_claude_client)
        return claude_client
    except Exception as e:
        logger.error(f"[LLMClient] Failed to initialize Claude client: {str(e)}", exc_info=True)
        raise


# Getter for Gemini client
def get_gemini_client():
    """Get a configured Gemini client instance."""
    genai.configure(api_key=GEMINI_API_KEY)
    return genai
