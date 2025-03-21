import asyncio
from typing import List

from api.v1.detectors.multi_agents.schema import EntryPoint
from api.v1.tools.helpers.duckduckgo import perform_duckduckgo_search
from api.v1.tools.schema import BuildQueriesResult
from api.v1.utilities.ast_tree.schema import ProjectAST
from config.prompts.build_query_ddg_prompt import (
    BUILD_QUERY_DDG_PROMPT,
    BUILD_QUERY_DDG_PROMPT_WITH_ENTRY_POINT,
)
from config.prompts.summarise_prompt import CLEAN_RESPONSE_PROMPT
from config.settings import LLM_SCAN_3
from core.llm.send_prompt_to_llm import send_prompt_to_llm_async
from core.utils.errors import LLMError, QueryGenerationError, SearchError
from core.utils.logger import logger

# Semaphore to control concurrent DuckDuckGo requests
# Limiting to 3 concurrent requests to avoid rate limiting
DDG_SEMAPHORE = asyncio.Semaphore(3)
# Delay between API calls in seconds
DDG_REQUEST_DELAY = 0.5


async def build_queries(
    contracts: str, docs: str, num_queries: int, entry_point: EntryPoint = None
) -> List[str]:
    """
    Build search queries based on contract code.

    Args:
        contracts: Contract code to analyze
        docs: Documentation to consider
        num_queries: Number of queries to generate
        entry_point: Optional entry point information

    Returns:
        List of generated search queries

    Raises:
        QueryGenerationError: If there's an error generating queries
        LLMError: If there's an error with the LLM
    """
    try:
        logger.info("[Tools] Building queries...")

        prompt = (
            BUILD_QUERY_DDG_PROMPT_WITH_ENTRY_POINT.format(
                contracts=contracts, docs=docs, num_queries=num_queries, entry_point=entry_point
            )
            if entry_point
            else BUILD_QUERY_DDG_PROMPT.format(
                contracts=contracts, docs=docs, num_queries=num_queries
            )
        )

        response = await send_prompt_to_llm_async(
            model_type=LLM_SCAN_3, messages=prompt, response_model=BuildQueriesResult
        )
        logger.info(f"[Tools] {num_queries} queries generated successfully: {response.queries}")

        return response.queries
    except LLMError:
        # Let LLM errors propagate to be handled by the route
        raise
    except Exception as e:
        logger.exception(f"[Tools] Error building queries: {e}")
        raise QueryGenerationError(
            message="Failed to generate search queries", details={"error": str(e)}
        )


async def execute_queries(queries: List[str], docs: str, ast_tree: ProjectAST = None) -> str:
    """
    Execute a list of queries in parallel and return the summarized results.

    Args:
        queries: List of search queries
        ast_tree: Abstract syntax tree of the contracts
        docs: Documentation related to the contracts

    Returns:
        str: Summarized results

    Raises:
        SearchError: If there's an error in the search process
        LLMError: If there's an error with the LLM
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

    try:
        # Execute all queries in parallel with controlled concurrency
        results = await asyncio.gather(
            *[execute_single_query(query) for query in queries], return_exceptions=True
        )

        # Filter out exceptions and empty results
        valid_results = []
        has_search_errors = False

        for i, result in enumerate(results):
            if isinstance(result, Exception):
                logger.warning(f"[Tools] Query {i + 1} failed: {str(result)}")
                # Track if we have any SearchError
                if isinstance(result, SearchError):
                    has_search_errors = True
            elif result:  # Only add non-empty results
                valid_results.append(result)

        # If all queries failed and we had at least one SearchError, propagate the error
        if not valid_results and has_search_errors and queries:
            raise SearchError(message="All search queries failed", details={"queries": queries})

        # If no results were found, return an empty string
        if not valid_results:
            return ""

        # summarise all the results from the queries
        logger.info("[Tools] Cleaning the response from DDG")
        return await _clean_response(docs=docs, ast=ast_tree, search_results=valid_results)
    except LLMError:
        # Let LLM errors propagate
        raise
    except SearchError:
        # Let search errors propagate
        raise
    except Exception as e:
        logger.exception(f"[Tools] Error executing queries: {e}")
        raise SearchError(
            message="Failed to execute search queries",
            details={"error": str(e), "query_count": len(queries)},
        )


async def _clean_response(search_results: List[str], ast: ProjectAST, docs: str) -> str:
    """
    Clean the response from search results.

    Args:
        docs: Documentation related to the contracts
        ast: Abstract syntax tree of the contracts
        search_results: List of search result strings to clean and summarize

    Returns:
        str: Cleaned and summarized response

    Raises:
        LLMError: If there's an error with the LLM
    """
    # Join the summary strings into a single string
    search_results_str = "".join([s for s in search_results if s])

    clean_response_prompt = CLEAN_RESPONSE_PROMPT.format(
        docs=docs, ast=str(ast), search_results=search_results_str
    )
    response: str | None = await send_prompt_to_llm_async(
        model_type=LLM_SCAN_3,
        messages=clean_response_prompt,
    )
    return response or ""
