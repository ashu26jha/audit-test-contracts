from typing import Optional
from fastapi import HTTPException
import asyncio
from common import logger
from common.send_prompt_to_llm import send_prompt_to_llm_async
from config.settings import LLM_MODEL_BEST, MAX_RETRIES, DELAY
from common.profiles import Profiles, load_profile

async def get_fuzz_test(prompt: str, system_prompt: str, detected_profile: Profiles) -> str:
    """
    Sends the fuzz test prompt to the LLM and retrieves the fuzz test.

    Args:
        prompt (str): The prompt to send to the LLM.
        system_prompt (str): The system prompt for the LLM.

    Returns:
        str: The fuzz test from the LLM response.
    """
    try:
        for attempt in range(1, MAX_RETRIES + 1):
            try:
                message_history = load_profile(detected_profile)
                llm_response: Optional[str] = await send_prompt_to_llm_async(
                    LLM_MODEL_BEST,
                    prompt,
                    system_prompt,
                    message_history,
                )

                if not llm_response or not isinstance(llm_response, str):
                    logger.warning("LLM response was empty or invalid")
                    raise HTTPException(status_code=500, detail="Internal Server Error")

                return llm_response

            except Exception as e:
                if attempt < MAX_RETRIES:
                    logger.warning(f"Attempt {attempt} failed. Retrying in {DELAY} seconds...")
                    await asyncio.sleep(DELAY)
                else:
                    logger.exception(f"All {MAX_RETRIES} attempts failed. Error: {str(e)}")
                    raise HTTPException(status_code=500, detail="Internal Server Error")
    except Exception as e:
        logger.exception(f"Error in perform_fuzz_test: {str(e)}")
        raise