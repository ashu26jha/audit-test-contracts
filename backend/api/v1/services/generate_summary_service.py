import re

from api.v1.prompts.generate_summary_prompts import system_prompt
from common.send_prompt_to_LLM import send_prompt_to_llm_async


async def generate_summary(contract: str) -> str:
    # For generating summary, we cheapest models works best with our needs
    raw_call = await send_prompt_to_llm_async("gpt-4o-mini", contract, system_prompt)
    json_match = re.search(r"```json(.*?)```", raw_call, re.DOTALL)
    return json_match.group(1)
