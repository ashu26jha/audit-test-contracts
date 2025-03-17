import asyncio
from typing import List

from api.v1.detectors.multi_agents.schema import EntryPoint
from api.v1.tools.helpers.duckduckgo import perform_duckduckgo_search
from api.v1.tools.schema import BuildQueriesResult
from config.prompts.build_query_ddg_prompt import (
    BUILD_QUERY_DDG_PROMPT,
    BUILD_QUERY_DDG_PROMPT_WITH_ENTRY_POINT,
)
from config.prompts.summarise_prompt import CLEAN_RESPONSE_PROMPT
from config.settings import LLM_SCAN_3
from core.llm.send_prompt_to_llm import send_prompt_to_llm_async
from core.utils.logger import logger

# Semaphore to control concurrent DuckDuckGo requests
# Limiting to 3 concurrent requests to avoid rate limiting
DDG_SEMAPHORE = asyncio.Semaphore(3)
# Delay between API calls in seconds
DDG_REQUEST_DELAY = 0.5


async def build_queries(
    contracts: str, docs: str, num_queries: int, entry_point: EntryPoint = None
) -> List[str]:

    logger.info("[Tools] Building queries...")

    prompt = (
        BUILD_QUERY_DDG_PROMPT_WITH_ENTRY_POINT.format(
            contracts=contracts, docs=docs, num_queries=num_queries, entry_point=entry_point
        )
        if entry_point
        else BUILD_QUERY_DDG_PROMPT.format(contracts=contracts, docs=docs, num_queries=num_queries)
    )

    response = await send_prompt_to_llm_async(
        model_type=LLM_SCAN_3, messages=prompt, response_model=BuildQueriesResult
    )

    logger.info(f"[Tools] {num_queries} queries generated successfully: {response.queries}")
    return response.queries


async def execute_queries(queries: List[str], docs: str, ast_tree: str = None) -> str:
    """
    Execute a list of queries in parallel and return the summarized results.

    Args:
        queries: List of search queries
        ast_tree: Abstract syntax tree of the contracts
        docs: Documentation related to the contracts

    Returns:
        str: Summarized results
    """
    if not queries:
        return ""

    logger.info(f"[Tools] Executing {len(queries)} queries in parallel with rate limiting")

    async def execute_single_query(query: str) -> str:
        """Execute a single query with rate limiting"""
        async with DDG_SEMAPHORE:
            # Add a small delay to avoid rate limiting
            await asyncio.sleep(DDG_REQUEST_DELAY)
            return await perform_duckduckgo_search(query=query)

    # Execute all queries in parallel with controlled concurrency
    results = await asyncio.gather(
        *[execute_single_query(query) for query in queries], return_exceptions=True
    )

    # Filter out exceptions and empty results
    valid_results = []
    for i, result in enumerate(results):
        if isinstance(result, Exception):
            logger.warning(f"[Tools] Query {i + 1} failed: {str(result)}")
        elif result:  # Only add non-empty results
            valid_results.append(result)

    # If no results were found, return an empty string
    if not valid_results:
        return ""

    # summarise all the results from the queries
    logger.info("[Tools] Cleaning the response from DDG")
    return await _clean_response(docs=docs, ast=ast_tree, search_results=valid_results)


async def _clean_response(search_results: List[str], ast: str, docs: str) -> str:
    """
    Clean the response from search results.

    Args:
        docs: Documentation related to the contracts
        ast: Abstract syntax tree of the contracts
        search_results: List of search result strings to clean and summarize

    Returns:
        str: Cleaned and summarized response
    """
    # Join the summary strings into a single string
    search_results_str = "".join([s for s in search_results if s])

    clean_response_prompt = CLEAN_RESPONSE_PROMPT.format(
        docs=docs, ast=ast, search_results=search_results_str
    )
    response: str | None = await send_prompt_to_llm_async(
        model_type=LLM_SCAN_3,
        messages=clean_response_prompt,
    )
    return response or ""
