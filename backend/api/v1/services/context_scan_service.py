from typing import List, Optional

from fastapi import HTTPException

from api.v1.helpers.retry_helper import retry_async_operation
from api.v1.schemas.context_scan_schema import ContextScanResponse, Finding
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
) -> List[Finding]:
    """
    Performs a context scan using an LLM and returns structured findings as a list.
    """
    # Determine if system prompt should be used
    system_prompt = SYSTEM_PROMPT if profile != Profiles.NONE else None

    # Select the appropriate prompt based on the presence of a summary
    prompt = (
        CONTEXT_PROMPT_WITH_SUMMARY.format(summary=summary, flattened_contracts=contracts)
        if summary
        else CONTEXT_PROMPT_WITHOUT_SUMMARY.format(flattened_contracts=contracts)
    )

    try:
        message_history = load_profile(Profiles.DEFAULT)
        llm_response: Optional[ContextScanResponse] = await retry_async_operation(
            send_prompt_to_llm_async,
            model,
            prompt,
            system_prompt,
            message_history,
            ContextScanResponse,
        )

        if not llm_response or not isinstance(llm_response, ContextScanResponse):
            logger.warning("LLM response was empty or invalid")
            raise HTTPException(status_code=500, detail="Internal Server Error")

        logger.info(f"Context scan completed successfully with {model}")

        return llm_response.findings

    except Exception as e:
        logger.exception(f"Unexpected Error: {str(e)}")
        raise HTTPException(status_code=500, detail="Internal Server Error")
