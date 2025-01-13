import json
from asyncio import Semaphore, sleep
from typing import List, Optional, Type, TypeVar

import google.generativeai as genai
import httpx
from anthropic import APIError as AnthropicError
from fastapi import HTTPException
from langfuse.decorators import langfuse_context, observe
from langfuse.openai import AsyncOpenAI
from openai import OpenAIError
from pydantic import BaseModel, ValidationError

from config.settings import SUPPORTED_MODELS
from core.llm.llm_clients import get_claude_client, get_gemini_client
from core.llm.parse_llm_response import parse_model_response
from core.schemas.llm_schema import Message
from core.utils.logger import logger
from core.utils.token_count import count_tokens

# Limit concurrent OpenAI requests
OPENAI_SEMAPHORE = Semaphore(4)
REQUEST_DELAY = 0.5  # seconds

# Per-request timeout
REQUEST_TIMEOUT = 240.0  # 4 minutes per request
CONNECT_TIMEOUT = 5.0  # 5 seconds for connection

T = TypeVar("T", bound=BaseModel)


@observe(as_type="generation")
async def send_prompt_to_llm_async(
    model_type: str,
    user_input: str,
    system_prompt: Optional[str] = None,
    message_history: Optional[List[Message]] = None,
    response_model: Optional[Type[T]] = None,
) -> Optional[T]:
    """
    Send a prompt to the specified LLM model asynchronously and optionally enforce strict JSON output.

    Args:
        model_type (str): The model type to use.
        user_input (str): The user's input text.
        system_prompt (Optional[str]): The system prompt or context.
        message_history (Optional[List[Message]]): The conversation history.
        response_model (Optional[Type[T]]): The Pydantic model to enforce strict JSON output.

    Returns:
        Optional[T]: The structured response from the LLM as an instance of response_model or raw string if no model is provided.
    """
    if message_history is None:
        message_history = []

    try:
        _validate_model(model_type)

        messages = _build_messages(model_type, user_input, system_prompt, message_history)
        token_count = count_tokens(str(messages))
        logger.debug(f"Message length: {token_count} tokens")

        if model_type in SUPPORTED_MODELS["openai"]:
            async with OPENAI_SEMAPHORE:
                await sleep(REQUEST_DELAY)
                timeout = httpx.Timeout(REQUEST_TIMEOUT, connect=CONNECT_TIMEOUT)

                async with AsyncOpenAI(timeout=timeout) as client:
                    try:
                        params = {
                            "model": model_type,
                            "messages": messages,
                            "response_format": response_model,
                        }
                        if "o1" in model_type:
                            params["reasoning_effort"] = "high"

                        if response_model:
                            response = await client.beta.chat.completions.parse(**params)
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
            try:
                claude_client = get_claude_client()
                response = await claude_client.completions.create(
                    model=model_type,
                    system=system_prompt if system_prompt else "",
                    messages=messages,
                    max_tokens=8192,
                    response_model=response_model,
                    timeout=REQUEST_TIMEOUT,
                )

                _update_langfuse(model_type, token_count, count_tokens(str(response)))

                return response
            except AnthropicError as e:
                logger.error(
                    f"[LLMPrompt] Anthropic API error for {model_type}: {str(e)}", exc_info=True
                )
                raise HTTPException(status_code=500, detail="LLM API Error") from e

        elif model_type in SUPPORTED_MODELS["gemini"]:
            try:
                gemini_client = get_gemini_client()
                gemini_model = gemini_client.GenerativeModel(model_type)
                prompt = _build_gemini_prompt(
                    user_input, system_prompt, message_history, response_model
                )

                response = await gemini_model.generate_content_async(
                    prompt,
                    generation_config=genai.GenerationConfig(
                        response_mime_type="application/json",
                        temperature=0.1,
                    ),
                )

                try:
                    parsed_json = json.loads(response.text)
                    structured_response = response_model.model_validate(parsed_json)
                except (json.JSONDecodeError, ValidationError):
                    logger.info(
                        "Initial Gemini structured output failed, trying to parse model response..."
                    )
                    structured_response = parse_model_response(
                        response.text, response_model, model_type=model_type
                    )

                # Extract token usage from Gemini's response
                usage = response._result.usage_metadata
                if not usage:
                    logger.warning(
                        f"No usage metadata available for {model_type}, falling back to estimates"
                    )

                prompt_tokens = usage.prompt_token_count if usage else token_count
                completion_tokens = (
                    usage.candidates_token_count
                    if usage
                    else count_tokens(str(structured_response))
                )
                total_tokens = usage.total_token_count if usage else None

                _update_langfuse(model_type, prompt_tokens, completion_tokens, total_tokens)

                return structured_response
            except Exception as e:
                logger.error(f"Gemini API error for {model_type}: {e}")
                raise HTTPException(status_code=500, detail="LLM API Error") from e

        else:
            raise HTTPException(status_code=500, detail=f"Unsupported model type: {model_type}")

    except Exception as e:
        langfuse_context.update_current_trace(
            metadata={"error": str(e), "error_type": type(e).__name__}
        )
        logger.exception(f"Unexpected error when sending prompt to {model_type}: {e}")
        raise HTTPException(status_code=500, detail="Internal Server Error") from e


def _validate_model(model_type: str) -> None:
    """Validate that the model type is supported."""
    for _, models in SUPPORTED_MODELS.items():
        if model_type in models:
            return
    raise HTTPException(status_code=500, detail=f"Unsupported model type: {model_type}")


def _build_messages(
    model_type: str,
    user_input: str,
    system_prompt: Optional[str],
    message_history: List[Message],
) -> List[Message]:
    """
    Build messages for OpenAI and Anthropic models.

    Args:
        model_type: The type of model to build messages for
        user_input: The user's input text
        system_prompt: Optional system prompt
        message_history: List of previous messages

    Returns:
        List[Message]: List of messages in the format expected by OpenAI and Anthropic
    """
    messages: List[Message] = []

    if "o1" in model_type:
        role = "developer"
    else:
        role = "system"

    # For OpenAI models, handle system prompt
    if system_prompt and model_type in SUPPORTED_MODELS["openai"]:
        messages.append({"role": role, "content": system_prompt})

    # Add message history if any
    if message_history:
        messages.extend(message_history)

    # Add user input
    messages.append({"role": "user", "content": user_input})

    return messages


def _build_gemini_prompt(
    user_input: str,
    system_prompt: Optional[str],
    message_history: List[Message],
    response_model: Optional[Type[T]],
) -> str:
    """
    Build a formatted string prompt for Gemini models.

    Args:
        user_input: The user's input text
        system_prompt: Optional system prompt
        message_history: List of previous messages

    Returns:
        str: Formatted prompt string for Gemini
    """
    full_prompt = ""
    if system_prompt:
        full_prompt += f"System: {system_prompt}\n\n"
    for msg in message_history:
        full_prompt += f"{msg['role'].capitalize()}: {msg['content']}\n"

    if response_model:
        try:
            schema_dict = response_model.model_json_schema()
            full_prompt += (
                "The JSON must follow this structure:\n" f"{json.dumps(schema_dict, indent=2)}\n"
            )
        except Exception:
            pass

    full_prompt += f"User: {user_input}"

    return full_prompt


def _update_langfuse(
    model_type: str, input_tokens: int, output_tokens: int, total_tokens: Optional[int] = None
):
    langfuse_context.update_current_observation(
        model=model_type,
        usage={
            "input": input_tokens,
            "output": output_tokens,
            "total": total_tokens,
        },
    )
