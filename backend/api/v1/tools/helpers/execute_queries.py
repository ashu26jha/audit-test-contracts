from typing import List

from api.v1.detectors.multi_agents.schema import EntryPoint
from api.v1.tools.helpers.duckduckgo import clean_response, perform_duckduckgo_search
from config.prompts.build_query_ddg_prompt import (
    BUILD_QUERY_DDG_PROMPT,
    BUILD_QUERY_DDG_PROMPT_WITH_ENTRY_POINT,
)
from config.settings import LLM_SCAN_3
from core.llm.send_prompt_to_llm import send_prompt_to_llm_async
from core.utils.logger import logger


async def build_queries(
    contracts: str, docs: str, num_queries: int, entry_point: EntryPoint = None
) -> List[str]:
    from api.v1.tools.schema import BuildQueriesResult

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
    return response.queries


async def execute_queries(queries: List[str], docs: str, ast_tree: str = None) -> List[str]:
    results = []
    for query in queries:
        ddg_results = await perform_duckduckgo_search(query=query)
        results.append(ddg_results)

    # summarise all the results from the queries
    logger.info("Cleaning the response from DDG")
    summarised_results = await clean_response(results, ast_tree, docs=docs)
    return summarised_results


async def build_and_execute_queries(
    contracts: str,
    docs: str,
    num_queries: int,
    entry_point: EntryPoint = None,
    ast_tree: str = None,
) -> List[str]:
    """
    Args:
        contracts: str
        docs: str
    Returns:
        List[str]
    Builds queries and executes them to get the summarised results.
    """
    queries = await build_queries(contracts, docs, num_queries, entry_point)
    logger.info(f"Queries: {queries}")
    return await execute_queries(queries, ast_tree, docs)
