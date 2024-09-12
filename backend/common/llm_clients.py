import anthropic
import openai

from config.settings import OPENAI_API_KEY, ANTHROPIC_API_KEY

# Check for required API keys
if not OPENAI_API_KEY:
    raise ValueError("Missing OPENAI_API_KEY in environment variables")

if not ANTHROPIC_API_KEY:
    raise ValueError("Missing ANTHROPIC_API_KEY in environment variables")

# Set up LLM clients
openai.api_key = OPENAI_API_KEY
OPENAI_CLIENT = openai

CLAUDE_CLIENT = anthropic.Anthropic(api_key=ANTHROPIC_API_KEY)
