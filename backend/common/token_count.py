from __future__ import annotations

import tiktoken
from config.settings import TOKENS_ENCODING


def count_tokens(text):
    enc = tiktoken.get_encoding(TOKENS_ENCODING)
    tokens = enc.encode(text)
    return len(tokens)
