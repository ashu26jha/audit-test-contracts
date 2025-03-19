import asyncio
import gc
import time
from typing import Dict, List, Optional

from langfuse.decorators import observe

from api.v1.detectors.context_scan.schema import FindingList
from api.v1.utilities.invariants.schema import InvariantsResponse
from config.settings import LLM_SCAN_3
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
    duckduckgo_results: Optional[str] = None,
    profile: Profiles = Profiles.NONE,
    model: str = LLM_SCAN_3,
    contract_language: str = "solidity",
) -> FindingList:
    try:
        # Build context scan specific prompt
        formatted_prompt = _prompt_builder.build_context_scan_prompt(
            contracts,
            summary,
            docs,
            invariants,
            duckduckgo_results,
            contract_language,
        )

        # Build full messages with profile
        messages = _prompt_builder.build_messages(
            model_type=model,
            user_input=formatted_prompt,
            profile=profile,
        )

        # Send prompt to LLM
        start_time = time.time()
        llm_response: Optional[FindingList] = await retry_async_operation(
            send_prompt_to_llm_async,
            model_type=model,
            messages=messages,
            response_model=FindingList,
        )
        elapsed = time.time() - start_time

        if not llm_response or not isinstance(llm_response, FindingList):
            logger.error("[ContextScan] LLM response was empty or invalid")
            return FindingList(findings=[])

        # Log success and return findings
        logger.debug(
            f"[ContextScan] Scan completed successfully for {model} with {len(llm_response.findings)} findings in {elapsed:.2f}s"
        )
        return llm_response

    except Exception as e:
        logger.error(
            f"[ContextScan] Context scan failed for model {model}: {str(e)}", exc_info=True
        )
        return FindingList(findings=[])


async def run_context_scan_batch(
    contracts: str,
    summary: Optional[str],
    docs: Optional[str],
    invariants: Optional[InvariantsResponse],
    duckduckgo_results: Optional[str],
    batch_configs: List[Dict],
    contract_language: str = "solidity",
) -> List[FindingList]:
    """Run multiple context scans in a batch"""
    try:
        tasks = []
        for config in batch_configs:
            task = run_context_scan(
                contracts=contracts,
                summary=summary,
                docs=docs,
                invariants=invariants,
                duckduckgo_results=duckduckgo_results,
                profile=config["profile"],
                model=config["model"],
                contract_language=contract_language,
            )
            tasks.append(task)

        # Run all tasks concurrently and gather results
        results = await asyncio.gather(*tasks, return_exceptions=True)
        return [
            result if not isinstance(result, Exception) else FindingList(findings=[])
            for result in results
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
