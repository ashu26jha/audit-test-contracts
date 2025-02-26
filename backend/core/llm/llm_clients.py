import google.generativeai as genai
import httpx
import instructor
import openai
from anthropic import AsyncAnthropic
from openai import OpenAI

from config.settings import ANTHROPIC_API_KEY, GEMINI_API_KEY, OPENAI_API_KEY, XAI_API_KEY
from core.utils.errors import ConfigurationError
from core.utils.logger import logger

# Check for required API keys
if not OPENAI_API_KEY:
    logger.error("Missing OPENAI_API_KEY in environment variables")
    raise ConfigurationError(
        message="Missing OpenAI API key. OpenAI client is required to run the application.",
        details={"missing_key": "OPENAI_API_KEY"},
    )

if not ANTHROPIC_API_KEY:
    logger.error("Missing ANTHROPIC_API_KEY in environment variables")
    raise ConfigurationError(
        message="Missing Anthropic API key. Claude client is required to run the application.",
        details={"missing_key": "ANTHROPIC_API_KEY"},
    )

if not GEMINI_API_KEY:
    logger.error(
        "Missing GEMINI_API_KEY in environment variables. Gemini client will not be available."
    )

if not XAI_API_KEY:
    logger.error("Missing XAI_API_KEY in environment variables. Grok client will not be available.")


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
    genai.configure(api_key=GEMINI_API_KEY, enable_prompt_caching=True)
    return genai


# Getter for Grok client
def get_grok_client():
    """Get a configured Grok client instance."""
    grok = OpenAI(
        api_key=XAI_API_KEY,
        base_url="https://api.x.ai/v1",
    )
    return grok
