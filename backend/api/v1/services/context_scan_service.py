import asyncio
from typing import List, Optional

from api.v1.schemas.context_scan_schema import ContextScanResponse, Finding
from common.logger import logger
from common.profiles import Profiles, load_profile
from common.send_prompt_to_llm import send_prompt_to_llm_async
from config.prompts.context_scan_prompts import (
    CONTEXT_PROMPT_WITH_SUMMARY,
    CONTEXT_PROMPT_WITHOUT_SUMMARY,
    SYSTEM_PROMPT,
)
from config.settings import DELAY, LLM_MODEL, MAX_RETRIES
from fastapi import HTTPException


async def perform_context_scan(
    summary: Optional[str], contracts: str, profile: Profiles = Profiles.NONE
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
        for attempt in range(1, MAX_RETRIES + 1):
            try:
                message_history = load_profile(Profiles.DEFAULT)
                llm_response: Optional[ContextScanResponse] = await send_prompt_to_llm_async(
                    LLM_MODEL, prompt, system_prompt, message_history, ContextScanResponse
                )

                if not llm_response or not isinstance(llm_response, ContextScanResponse):
                    logger.warning("LLM response was empty or invalid")
                    raise HTTPException(status_code=500, detail="Internal Server Error")

                return llm_response.findings

            except Exception as e:
                if attempt < MAX_RETRIES:
                    logger.warning(f"Attempt {attempt} failed. Retrying in {DELAY} seconds...")
                    await asyncio.sleep(DELAY)
                else:
                    logger.exception(f"All {MAX_RETRIES} attempts failed. Error: {str(e)}")
                    raise HTTPException(status_code=500, detail="Internal Server Error")

    except HTTPException:
        raise
    except Exception as e:
        logger.exception(f"Unexpected Error: {str(e)}")
        raise HTTPException(status_code=500, detail="Internal Server Error")
