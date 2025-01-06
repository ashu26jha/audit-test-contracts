import google.generativeai as genai
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

# Set up OpenAI client
openai.api_key = OPENAI_API_KEY
OPENAI_CLIENT = openai

# Set up Anthropic client
base_claude_client = AsyncAnthropic(api_key=ANTHROPIC_API_KEY)
CLAUDE_CLIENT = instructor.from_anthropic(base_claude_client)

# Set up Gemini client
genai.configure(api_key=GEMINI_API_KEY)
GEMINI_CLIENT = genai
