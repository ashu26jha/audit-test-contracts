import json
from asyncio import Semaphore, sleep
from collections import defaultdict
from typing import List, Optional, Type, TypeVar, Union

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

# Global limit of 6 concurrent requests across *all* models
GLOBAL_SEMAPHORE = Semaphore(6)

# Per-model limit of 2 concurrent requests
MODEL_SEMAPHORES = defaultdict(lambda: Semaphore(3))

# Per-request timeout
REQUEST_DELAY = 0.5  # seconds
REQUEST_TIMEOUT = 240.0  # 4 minutes per request
CONNECT_TIMEOUT = 5.0  # 5 seconds for connection

T = TypeVar("T", bound=BaseModel)


@observe(as_type="generation")
async def send_prompt_to_llm_async(
    model_type: str,
    messages: Union[str, List[Message]],
    response_model: Optional[Type[T]] = None,
) -> Optional[T]:
    """
    Send pre-formatted messages to the specified LLM model asynchronously.

    Args:
        model_type (str): The model type to use.
        messages (Union[str, List[Message]]): Pre-formatted messages or prompt string.
        response_model (Optional[Type[T]]): The Pydantic model to enforce strict JSON output.

    Returns:
        Optional[T]: The structured response from the LLM.
    """
    try:
        async with GLOBAL_SEMAPHORE:
            async with MODEL_SEMAPHORES[model_type]:
                _validate_model(model_type)

                # Convert string to message array for OpenAI/Anthropic
                if isinstance(messages, str) and model_type not in SUPPORTED_MODELS["gemini"]:
                    messages = [{"role": "user", "content": messages}]

                token_count = count_tokens(str(messages))
                logger.debug(f"[LLMPrompt] Message length: {token_count} tokens for {model_type}")

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
                            if "o1" in model_type:
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
                                logger.error(f"Rate limit hit for {model_type}: {e}")
                            raise

                elif model_type in SUPPORTED_MODELS["anthropic"]:
                    try:
                        claude_client = get_claude_client()
                        response = await claude_client.completions.create(
                            model=model_type,
                            messages=messages,
                            max_tokens=8192,
                            response_model=response_model,
                            timeout=REQUEST_TIMEOUT,
                        )

                        _update_langfuse(model_type, token_count, count_tokens(str(response)))

                        return response
                    except AnthropicError as e:
                        logger.error(
                            f"[LLMPrompt] Anthropic API error for {model_type}: {str(e)}",
                            exc_info=True,
                        )
                        raise HTTPException(status_code=500, detail="LLM API Error") from e

                elif model_type in SUPPORTED_MODELS["gemini"]:
                    try:
                        gemini_client = get_gemini_client()
                        gemini_model = gemini_client.GenerativeModel(model_type)

                        response = await gemini_model.generate_content_async(
                            messages,
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
                    raise HTTPException(
                        status_code=500, detail=f"Unsupported model type: {model_type}"
                    )

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
