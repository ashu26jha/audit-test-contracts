from typing import Tuple

from fastapi import HTTPException

from api.v1.utilities.summary.schema import SummaryResponse
from config.prompts.summary_prompts import SUMMARY_PROMPT
from config.settings import LLM_UTILITY
from core.llm.send_prompt_to_llm import send_prompt_to_llm_async
from core.utils.logger import logger


async def generate_summary(contracts: str) -> Tuple[str, str]:
    logger.info("[Summary] Starting summary generation task...")
    try:
        prompt = SUMMARY_PROMPT.format(contracts=contracts)
        llm_response = await send_prompt_to_llm_async(
            model_type=LLM_UTILITY,
            messages=prompt,
            response_model=SummaryResponse,
        )

        if not llm_response or not isinstance(llm_response, SummaryResponse):
            logger.warning("[Summary] LLM response was empty or invalid")
            raise HTTPException(status_code=500, detail="Internal Server Error")

        summary = llm_response.summary
        contract_type = llm_response.type

        if not summary or not contract_type:
            logger.warning("[Summary] Missing summary or contract type in parsed JSON.")
            raise HTTPException(status_code=500, detail="Internal Server Error")

        logger.info("[Summary] Summary generation successfully completed")

        return summary, contract_type

    except HTTPException:
        raise
    except Exception as e:
        logger.exception(f"[Summary] Unexpected error in generate_summary: {str(e)}")
        raise HTTPException(status_code=500, detail="Internal Server Error") from e
