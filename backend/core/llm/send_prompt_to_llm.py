import asyncio
import json
from asyncio import Semaphore, sleep
from typing import List, Optional, Type, TypeVar, Union

import google.generativeai as genai
import httpx
from anthropic import APIError as AnthropicError
from langfuse.decorators import langfuse_context, observe
from langfuse.openai import AsyncOpenAI
from openai import OpenAIError
from pydantic import BaseModel, ValidationError

from config.settings import SUPPORTED_MODELS, TEMPERATURE
from core.llm.llm_clients import get_claude_client, get_gemini_client, get_grok_client
from core.llm.parse_llm_response import parse_model_response
from core.schemas.llm_schema import Message
from core.utils.errors import (
    LLMError,
    ModelError,
    RateLimitError,
)
from core.utils.errors import ValidationError as AuditValidationError
from core.utils.logger import logger
from core.utils.token_count import count_tokens

# Global limit of 10 concurrent requests across *all* models
GLOBAL_SEMAPHORE = Semaphore(25)
MODEL_SEMAPHORE = 10

# Per-request timeout
REQUEST_DELAY = 0.5  # seconds
REQUEST_TIMEOUT = 300.0  # 5 minutes per request
CONNECT_TIMEOUT = 5.0  # 5 seconds for connection

T = TypeVar("T", bound=BaseModel)

# Replace the old MODEL_SEMAPHORES with a loop-aware dictionary:
_MODEL_SEMAPHORES_PER_LOOP = {}


@observe(name="llm_call", as_type="generation")
async def send_prompt_to_llm_async(
    model_type: str,
    messages: Union[str, List[Message]],
    response_model: Optional[Type[T]] = None,
    thinking: Optional[bool] = False,
) -> Optional[T]:
    """
    Send pre-formatted messages to the specified LLM model asynchronously.

    Args:
        model_type (str): The model type to use.
        messages (Union[str, List[Message]]): Pre-formatted messages or prompt string.
        response_model (Optional[Type[T]]): The Pydantic model to enforce strict JSON output.
        langfuse_parent_trace_id (Optional[str]): The parent trace ID to link this call to.

    Returns:
        Optional[T]: The structured response from the LLM.

    Raises:
        ModelError: If the model type is not supported
        RateLimitError: If rate limits are exceeded
        LLMError: If there's an error with the LLM API
        ValidationError: If response validation fails
        PromptError: If there's an error with prompt construction or token limits
    """

    try:
        async with GLOBAL_SEMAPHORE:
            sem = _get_model_semaphore(model_type)
            async with sem:
                _validate_model(model_type)

                # Convert string to message array for OpenAI/Anthropic
                if isinstance(messages, str) and model_type not in SUPPORTED_MODELS["gemini"]:
                    messages = [{"role": "user", "content": messages}]

                token_count = count_tokens(str(messages))
                logger.info(f"[LLMPrompt] Message length: {token_count} tokens for {model_type}")

                # -----------------------------------------
                # SUPPORT FOR GROK MODELS
                # -----------------------------------------

                if model_type in SUPPORTED_MODELS["grok"]:
                    try:
                        grok_client = get_grok_client()
                        params = {
                            "model": model_type,
                            "messages": messages,
                            "response_format": response_model,
                        }

                        if response_model:
                            response = await grok_client.beta.chat.completions.parse(**params)
                            structured_response: Optional[T] = response.choices[0].message.parsed
                        else:
                            response = await grok_client.chat.completions.create(
                                model=model_type,
                                messages=messages,
                            )
                            content = response.choices[0].message.content.strip()
                            structured_response = parse_model_response(content, response_model)

                        return structured_response
                    except OpenAIError as e:
                        if "rate_limit" in str(e).lower():
                            logger.error(f"[LLMPrompt] Rate limit hit for {model_type}: {e}")
                            raise RateLimitError(
                                message="Grok rate limit exceeded",
                                details={"model": model_type, "error": str(e)},
                            ) from e
                        raise LLMError(
                            message="Grok API error",
                            details={"model": model_type, "error": str(e)},
                        ) from e

                # -----------------------------------------
                # SUPPORT FOR OPENAI MODELS
                # -----------------------------------------

                if model_type in SUPPORTED_MODELS["openai"]:
                    await sleep(REQUEST_DELAY)
                    timeout = httpx.Timeout(REQUEST_TIMEOUT, connect=CONNECT_TIMEOUT)

                    async with AsyncOpenAI(timeout=timeout) as client:
                        try:
                            params = {
                                "model": model_type,
                                "messages": messages,
                                "response_format": response_model,
                            }
                            if "o1" in model_type or "o3" in model_type:
                                params["reasoning_effort"] = "high"

                            if response_model:
                                response = await client.beta.chat.completions.parse(**params)
                                structured_response: Optional[T] = response.choices[
                                    0
                                ].message.parsed
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
                                logger.error(f"[LLMPrompt] Rate limit hit for {model_type}: {e}")
                                raise RateLimitError(
                                    message="OpenAI rate limit exceeded",
                                    details={"model": model_type, "error": str(e)},
                                ) from e
                            logger.error(f"[LLMPrompt] OpenAI API error for {model_type}: {e}")
                            raise LLMError(
                                message="OpenAI API error",
                                details={"model": model_type, "error": str(e)},
                            ) from e

                # -----------------------------------------
                # SUPPORT FOR ANTHROPIC MODELS
                # -----------------------------------------

                elif model_type in SUPPORTED_MODELS["anthropic"]:
                    try:
                        claude_client = get_claude_client()
                        max_tokens = 60000 if "3-7" in model_type else 8192

                        # Create base parameters for the API call
                        api_params = {
                            "model": model_type,
                            "messages": messages,
                            "max_tokens": max_tokens,
                            "response_model": response_model,
                            "timeout": REQUEST_TIMEOUT,
                        }

                        # Add temperature parameter if thinking is False
                        if not thinking:
                            api_params["temperature"] = TEMPERATURE

                        # Add thinking parameter if thinking is True
                        if thinking:
                            api_params["thinking"] = {"type": "enabled", "budget_tokens": 30000}

                        response = await claude_client.completions.create(**api_params)

                        _update_langfuse(model_type, token_count, count_tokens(str(response)))

                        return response
                    except AnthropicError as e:
                        logger.error(
                            f"[LLMPrompt] Anthropic API error for {model_type}: {str(e)}",
                            exc_info=True,
                        )
                        raise LLMError(
                            message="Anthropic API error",
                            details={"model": model_type, "error": str(e)},
                        ) from e
                    except Exception as e:
                        logger.error(
                            f"[LLMPrompt] Unexpected error with Claude: {str(e)}", exc_info=True
                        )
                        raise

                # -----------------------------------------
                # SUPPORT FOR GEMINI MODELS
                # -----------------------------------------

                elif model_type in SUPPORTED_MODELS["gemini"]:
                    try:
                        gemini_client = get_gemini_client()
                        gemini_model = gemini_client.GenerativeModel(model_type)

                        response = await gemini_model.generate_content_async(
                            messages,
                            generation_config=genai.GenerationConfig(
                                response_mime_type="application/json",
                                temperature=TEMPERATURE,
                            ),
                        )

                        try:
                            parsed_json = json.loads(response.text)
                            structured_response = response_model.model_validate(parsed_json)
                        except (json.JSONDecodeError, ValidationError):
                            logger.info(
                                "[LLMPrompt] Initial Gemini structured output failed, trying to parse model response..."
                            )
                            structured_response = parse_model_response(
                                response.text, response_model, model_type=model_type
                            )

                        # Extract token usage from Gemini's response
                        usage = response._result.usage_metadata
                        if not usage:
                            logger.warning(
                                f"[LLMPrompt] No usage metadata available for {model_type}, falling back to estimates"
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
                        logger.error(f"[LLMPrompt] Gemini API error for {model_type}: {e}")
                        raise LLMError(
                            message="Gemini API error",
                            details={"model": model_type, "error": str(e)},
                        ) from e

                else:
                    raise ModelError(
                        message=f"Unsupported model type: {model_type}",
                        details={"model": model_type, "supported_models": SUPPORTED_MODELS},
                    )

    except (ModelError, RateLimitError, LLMError, AuditValidationError):
        raise
    except Exception as e:
        langfuse_context.update_current_trace(
            metadata={"error": str(e), "error_type": type(e).__name__}
        )
        logger.exception(f"[LLMPrompt] Unexpected error when sending prompt to {model_type}: {e}")
        raise LLMError(
            message="Unexpected error during LLM processing",
            details={"model": model_type, "error": str(e)},
        ) from e


def _get_model_semaphore(model_type: str) -> asyncio.Semaphore:
    """
    Retrieve or create a semaphore for the given model_type,
    scoped to the current event loop. This prevents cross-loop usage
    that leads to the "bound to a different event loop" error.
    """
    current_loop = asyncio.get_running_loop()
    if current_loop not in _MODEL_SEMAPHORES_PER_LOOP:
        _MODEL_SEMAPHORES_PER_LOOP[current_loop] = {}

    loop_semaphores = _MODEL_SEMAPHORES_PER_LOOP[current_loop]
    if model_type not in loop_semaphores:
        # You can customize the concurrency limit here if needed
        loop_semaphores[model_type] = asyncio.Semaphore(MODEL_SEMAPHORE)

    return loop_semaphores[model_type]


def _validate_model(model_type: str) -> None:
    """Validate that the model type is supported."""
    for _, models in SUPPORTED_MODELS.items():
        if model_type in models:
            return
    raise ModelError(
        message=f"Unsupported model type: {model_type}",
        details={"model": model_type, "supported_models": SUPPORTED_MODELS},
    )


def _update_langfuse(
    model_type: str, input_tokens: int, output_tokens: int, total_tokens: Optional[int] = None
):
    """Update Langfuse with token usage information."""
    try:

        langfuse_context.update_current_observation(
            model=model_type,
            usage={
                "input": input_tokens,
                "output": output_tokens,
                "total": total_tokens or (input_tokens + output_tokens),
            },
        )
    except Exception as e:
        logger.warning(f"Failed to update Langfuse metrics: {e}")
        # Don't raise - this is non-critical telemetry
