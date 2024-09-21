from typing import Tuple

from api.v1.prompts.generate_summary_prompts import SUMMARY_PROMPT
from api.v1.schemas.generate_summary_schema import SummaryResponse
from common import logger
from common.exceptions import EmptyResponseError, InternalServerError, JSONParsingError
from common.send_prompt_to_llm import send_prompt_to_llm_async
from config.settings import LLM_MODEL_SUMMARY


async def generate_summary(contracts: str) -> Tuple[str, str]:
    prompt = SUMMARY_PROMPT.format(contracts=contracts)

    try:
        llm_response = await send_prompt_to_llm_async(
            LLM_MODEL_SUMMARY, prompt, response_model=SummaryResponse
        )

        if not llm_response or not isinstance(llm_response, SummaryResponse):
            logger.warning("LLM response was empty or invalid")
            raise EmptyResponseError("LLM response was empty or invalid")

        summary = llm_response.summary
        contract_type = llm_response.type

        if not summary or not contract_type:
            logger.warning("Missing summary or contract type in parsed JSON.")
            raise JSONParsingError("Missing summary or contract type in parsed JSON.")

        return summary, contract_type

    except (EmptyResponseError, JSONParsingError):
        raise
    except Exception as e:
        logger.error(f"Unexpected error in generate_summary: {str(e)}")
        raise InternalServerError("Failed to generate summary") from e
