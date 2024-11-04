import asyncio
from asyncio import Semaphore
from typing import List, Optional, Type, TypeVar

# from langfuse.decorators import langfuse_context
import httpx
from fastapi import HTTPException
from openai import AsyncOpenAI, OpenAIError
from pydantic import BaseModel

from common import logger
from common.llm_clients import CLAUDE_CLIENT
from common.parse_llm_response import parse_model_response
from common.token_count import count_tokens
from config.settings import MODELS_NOT_SUPPORTING_SYSTEM, SUPPORTED_MODELS, TEMPERATURE

# Limit concurrent OpenAI requests
OPENAI_SEMAPHORE = Semaphore(3)
REQUEST_DELAY = 0.5  # seconds

# Per-request timeout
REQUEST_TIMEOUT = 240.0  # 4 minutes per request
CONNECT_TIMEOUT = 5.0  # 5 seconds for connection

T = TypeVar("T", bound=BaseModel)


async def send_prompt_to_llm_async(
    model_type: str,
    user_input: str,
    system_prompt: Optional[str] = None,
    message_history: Optional[List[dict]] = None,
    response_model: Optional[Type[T]] = None,
) -> Optional[T]:
    """
    Send a prompt to the specified LLM model asynchronously and optionally enforce strict JSON output.

    Args:
        model_type (str): The model type to use.
        user_input (str): The user's input text.
        system_prompt (Optional[str]): The system prompt or context.
        message_history (Optional[List[dict]]): The conversation history.
        response_model (Optional[Type[T]]): The Pydantic model to enforce strict JSON output.

    Returns:
        Optional[T]: The structured response from the LLM as an instance of response_model or raw string if no model is provided.
    """
    if message_history is None:
        message_history = []

    try:
        messages = build_messages(model_type, user_input, system_prompt, message_history)
        logger.debug(f"Message length: {count_tokens(str(messages))} tokens")

        if model_type in SUPPORTED_MODELS["openai"]:
            async with OPENAI_SEMAPHORE:
                await asyncio.sleep(REQUEST_DELAY)
                timeout = httpx.Timeout(REQUEST_TIMEOUT, connect=CONNECT_TIMEOUT)

                async with AsyncOpenAI(timeout=timeout) as client:
                    try:
                        if response_model and model_type not in MODELS_NOT_SUPPORTING_SYSTEM:
                            response = await client.beta.chat.completions.parse(
                                model=model_type,
                                messages=messages,
                                response_format=response_model,
                            )
                            structured_response: Optional[T] = response.choices[0].message.parsed
                        else:
                            response = await client.chat.completions.create(
                                model=model_type,
                                messages=messages,
                            )
                            content = response.choices[0].message.content.strip()
                            structured_response = parse_model_response(content, response_model)

                        return structured_response
                    except OpenAIError as e:
                        if "rate_limit" in str(e).lower():
                            logger.error(f"Rate limit hit for {model_type}: {e}")
                        raise

        elif model_type in SUPPORTED_MODELS["anthropic"]:
            response = CLAUDE_CLIENT.messages.create(
                model=model_type,
                system=system_prompt if system_prompt else "",
                messages=messages,
                max_tokens=8192,
                temperature=TEMPERATURE,
            )
            content = response.content[0].text.strip()

            # langfuse_context.update_current_observation(
            #     model=model_type,
            #     usage={
            #         "input": response.usage.input_tokens,
            #         "output": response.usage.output_tokens,
            #     },
            # )

            # Use the helper function to parse the content
            structured_response = parse_model_response(content, response_model)
            return structured_response

        else:
            raise HTTPException(status_code=500, detail=f"Unsupported model type: {model_type}")

    except OpenAIError as e:
        # langfuse_context.update_current_trace(metadata={"error": str(e)})
        logger.error(f"OpenAI API error when sending prompt to {model_type}: {e}")
        raise HTTPException(status_code=500, detail="Internal Server Error")
    except ValueError as e:
        # langfuse_context.update_current_trace(metadata={"error": str(e)})
        logger.error(f"Value error when sending prompt to {model_type}: {e}")
        raise HTTPException(status_code=500, detail="Internal Server Error")
    except Exception as e:
        # langfuse_context.update_current_trace(metadata={"error": str(e)})
        logger.exception(f"Unexpected error when sending prompt to {model_type}: {e}")
        raise HTTPException(status_code=500, detail="Internal Server Error")


def build_messages(
    model_type: str,
    user_input: str,
    system_prompt: Optional[str],
    message_history: List[dict],
) -> List[dict]:
    messages = []

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
