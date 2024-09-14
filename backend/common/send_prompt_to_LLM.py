from __future__ import annotations

import logging
from typing import List, Optional

from common.llm_clients import CLAUDE_CLIENT
from config.settings import MODELS_NOT_SUPPORTING_SYSTEM, SUPPORTED_MODELS, TEMPERATURE
from langfuse.decorators import langfuse_context
from openai import AsyncOpenAI


async def send_prompt_to_llm_async(
    model_type: str,
    user_input: str,
    system_prompt: Optional[str] = None,
    message_history: Optional[List[dict]] = None,
) -> Optional[str]:
    """
    Send a prompt to the specified LLM model asynchronously.

    Args:
        model_type (str): The model type to use.
        user_input (str): The user's input text.
        system_prompt (Optional[str]): The system prompt or context.
        message_history (Optional[List[dict]]): The conversation history.

    Returns:
        Optional[str]: The response from the LLM or None if an error occurs.
    """
    if message_history is None:
        message_history = []

    try:
        messages = build_messages(model_type, user_input, system_prompt, message_history)

        if model_type in SUPPORTED_MODELS["openai"]:
            async with AsyncOpenAI() as client:
                response = await client.chat.completions.create(
                    model=model_type,
                    messages=messages,
                )
            return response.choices[0].message.content.strip()

        elif model_type in SUPPORTED_MODELS["anthropic"]:
            response = CLAUDE_CLIENT.messages.create(
                model=model_type,
                system=system_prompt if system_prompt else "",
                messages=messages,
                max_tokens=8192,
                temperature=TEMPERATURE,
            )
            content = response.content[0].text.strip()

            langfuse_context.update_current_observation(
                model=model_type,
                usage={
                    "input": response.usage.input_tokens,
                    "output": response.usage.output_tokens,
                },
            )
            return content
        else:
            raise ValueError(f"Unsupported model type: {model_type}")

    except Exception as e:
        langfuse_context.update_current_trace(metadata={"error": str(e)})
        logging.error(f"Error sending prompt to {model_type}: {e}")
        return None


def build_messages(
    model_type: str,
    user_input: str,
    system_prompt: Optional[str],
    message_history: List[dict],
) -> List[dict]:

    messages = []

    # For OpenAI models, include the system prompt in the messages
    if system_prompt and model_type in SUPPORTED_MODELS["openai"]:
        messages.append({"role": "system", "content": system_prompt})

    # For OpenAI models, handle system prompt
    if system_prompt and model_type in SUPPORTED_MODELS["openai"]:
        if model_type not in MODELS_NOT_SUPPORTING_SYSTEM:
            # Include system prompt as 'system' role message
            messages.append({"role": "system", "content": system_prompt})

    # Add message history if any
    if message_history:
        messages.extend(message_history)

    # Add user input
    messages.append({"role": "user", "content": user_input})

    return messages
