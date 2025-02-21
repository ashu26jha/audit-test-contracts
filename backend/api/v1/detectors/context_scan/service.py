import asyncio
import gc
import time
from typing import Dict, List, Optional

from langfuse.decorators import observe

from api.v1.detectors.context_scan.schema import ContextScanResponse
from api.v1.utilities.invariants.schema import InvariantsResponse
from config.settings import LLM_SCAN_1
from core.llm.prompt_builder import PromptBuilder
from core.llm.send_prompt_to_llm import send_prompt_to_llm_async
from core.utils.logger import logger
from core.utils.profiles import Profiles
from core.utils.retry_helper import retry_async_operation

# Create singleton instance
_prompt_builder = PromptBuilder()


@observe(name="context_scan")
async def run_context_scan(
    contracts: str,
    summary: Optional[str],
    docs: Optional[str],
    invariants: Optional[InvariantsResponse],
    profile: Profiles = Profiles.NONE,
    model: str = LLM_SCAN_1,
) -> dict:
    try:
        # Build context scan specific prompt
        formatted_prompt = _prompt_builder.build_context_scan_prompt(
            contracts,
            summary,
            docs,
            invariants,
        )

        # Build full messages with profile
        messages = _prompt_builder.build_messages(
            model_type=model,
            user_input=formatted_prompt,
            profile=profile,
        )

        # Send prompt to LLM
        start_time = time.time()
        llm_response: Optional[ContextScanResponse] = await retry_async_operation(
            send_prompt_to_llm_async,
            model_type=model,
            messages=messages,
            response_model=ContextScanResponse,
        )
        elapsed = time.time() - start_time

        if not llm_response or not isinstance(llm_response, ContextScanResponse):
            logger.error("[ContextScan] LLM response was empty or invalid")
            return {"findings": []}

        # Convert Pydantic model to dict for serialization
        response_dict = {"findings": [finding.model_dump() for finding in llm_response.findings]}
        logger.debug(
            f"[ContextScan] Scan completed successfully for {model} with {len(response_dict['findings'])} findings in {elapsed:.2f}s"
        )
        return response_dict

    except Exception as e:
        logger.error(
            f"[ContextScan] Context scan failed for model {model}: {str(e)}", exc_info=True
        )
        return {"findings": []}


async def run_context_scan_batch(
    contracts: str,
    summary: Optional[str],
    docs: Optional[str],
    invariants: Optional[InvariantsResponse],
    batch_configs: List[Dict],
) -> List[dict]:
    """Run multiple context scans in a batch"""
    try:
        tasks = []
        for config in batch_configs:
            task = run_context_scan(
                contracts=contracts,
                summary=summary,
                docs=docs,
                invariants=invariants,
                profile=config["profile"],
                model=config["model"],
            )
            tasks.append(task)

        # Run all tasks concurrently and gather results
        results = await asyncio.gather(*tasks, return_exceptions=True)
        return [
            result if not isinstance(result, Exception) else {"findings": []} for result in results
        ]
    finally:
        # Cleanup after batch completion
        gc.collect()  # Force garbage collection
        tasks.clear()  # Clear task references

        # Clear large strings that were used for this batch
        contracts = None
        summary = None
        docs = None
        invariants = None
