from typing import Tuple

from fastapi import HTTPException

from api.v1.schemas.generate_summary_schema import SummaryResponse
from common import logger
from common.send_prompt_to_llm import send_prompt_to_llm_async
from config.prompts.summary_prompts import SUMMARY_PROMPT
from config.settings import LLM_MODEL_BEST_2


async def generate_summary(contracts: str) -> Tuple[str, str]:
    prompt = SUMMARY_PROMPT.format(contracts=contracts)

    try:
        llm_response = await send_prompt_to_llm_async(
            LLM_MODEL_BEST_2, prompt, response_model=SummaryResponse
        )

        if not llm_response or not isinstance(llm_response, SummaryResponse):
            logger.warning("LLM response was empty or invalid")
            raise HTTPException(status_code=500, detail="Internal Server Error")

        summary = llm_response.summary
        contract_type = llm_response.type

        if not summary or not contract_type:
            logger.warning("Missing summary or contract type in parsed JSON.")
            raise HTTPException(status_code=500, detail="Internal Server Error")

        return summary, contract_type

    except HTTPException:
        raise
    except Exception as e:
        logger.exception(f"Unexpected error in generate_summary: {str(e)}")
        raise HTTPException(status_code=500, detail="Internal Server Error")
