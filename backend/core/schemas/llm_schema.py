from typing import Literal, TypedDict


class Message(TypedDict):
    """TypedDict for message structure used in LLM requests."""

    role: Literal["system", "user", "assistant"]
    content: str
