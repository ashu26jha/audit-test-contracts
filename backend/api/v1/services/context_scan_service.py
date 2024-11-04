import time
from typing import Optional

from api.v1.helpers.retry_helper import retry_async_operation
from api.v1.schemas.context_scan_schema import ContextScanResponse
from common.logger import logger
from common.profiles import Profiles, load_profile
from common.send_prompt_to_llm import send_prompt_to_llm_async
from config.prompts.context_scan_prompts import (
    CONTEXT_PROMPT_WITH_SUMMARY,
    CONTEXT_PROMPT_WITHOUT_SUMMARY,
    SYSTEM_PROMPT,
)
from config.settings import LLM_MODEL_BEST


async def perform_context_scan(
    summary: Optional[str],
    contracts: str,
    profile: Profiles = Profiles.NONE,
    model: str = LLM_MODEL_BEST,
) -> ContextScanResponse:
    try:
        system_prompt = SYSTEM_PROMPT if profile != Profiles.NONE else None

        prompt = (
            CONTEXT_PROMPT_WITH_SUMMARY.format(summary=summary, flattened_contracts=contracts)
            if summary
            else CONTEXT_PROMPT_WITHOUT_SUMMARY.format(flattened_contracts=contracts)
        )

        message_history = load_profile(profile)
        start_time = time.time()
        llm_response: Optional[ContextScanResponse] = await retry_async_operation(
            send_prompt_to_llm_async,
            model,
            prompt,
            system_prompt,
            message_history,
            ContextScanResponse,
        )
        elapsed = time.time() - start_time
        logger.info(f"LLM response time: {elapsed:.2f}s for model {model}")

        if not llm_response or not isinstance(llm_response, ContextScanResponse):
            logger.error("LLM response was empty or invalid")
            return ContextScanResponse(findings=[])

        return llm_response

    except Exception as e:
        logger.error(f"Context scan failed for model {model}: {str(e)}")
        return ContextScanResponse(findings=[])
