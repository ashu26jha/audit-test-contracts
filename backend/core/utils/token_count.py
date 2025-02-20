import tiktoken

from config.settings import TOKENS_ENCODING
from core.utils.errors import ConfigurationError, ValidationError

if not TOKENS_ENCODING:
    raise ConfigurationError(
        "Missing token encoding configuration", details={"missing_fields": ["TOKENS_ENCODING"]}
    )


def count_tokens(text: str) -> int:
    """
    Count the number of tokens in a text using the configured encoding.

    Args:
        text: The text to count tokens for.

    Returns:
        int: The number of tokens in the text.

    Raises:
        ValidationError: If the text is not a string or if there's an encoding error.
    """
    try:
        enc = tiktoken.get_encoding(TOKENS_ENCODING)
        tokens = enc.encode(text)
        return len(tokens)
    except Exception as e:
        raise ValidationError(
            "Failed to encode text for token counting",
            details={"error": str(e), "encoding": TOKENS_ENCODING},
        ) from e
