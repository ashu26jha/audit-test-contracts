from typing import Tuple

from langfuse.decorators import observe

from api.v1.utilities.summary.schema import SummaryResponse
from config.prompts.summary_prompts import SUMMARY_PROMPT
from config.settings import LLM_UTILITY
from core.llm.send_prompt_to_llm import send_prompt_to_llm_async
from core.utils.errors import LLMError, ValidationError
from core.utils.logger import logger


@observe(name="summary_generation")
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
            raise ValidationError(
                message="Invalid LLM response", details="Response was empty or of incorrect type"
            )

        summary = llm_response.summary
        contract_type = llm_response.type

        if not summary or not contract_type:
            logger.warning("[Summary] Missing summary or contract type in parsed JSON.")
            raise ValidationError(
                message="Invalid LLM response", details="Missing required fields in response"
            )

        logger.info("[Summary] Summary generation successfully completed")
        return summary, contract_type

    except (LLMError, ValidationError):
        # Let domain errors propagate up
        raise
    except Exception as e:
        logger.exception(f"[Summary] Unexpected error in generate_summary: {str(e)}")
        raise LLMError(
            message="Unexpected error during summary generation", details={"error": str(e)}
        ) from e
