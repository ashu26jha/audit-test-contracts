import os
import sys
import tiktoken


# Add the root directory to the Python path
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from backend.config import settings


def count_tokens(text):
    enc = tiktoken.get_encoding(settings.TOKENS_ENCODING)
    tokens = enc.encode(text)
    return len(tokens)
