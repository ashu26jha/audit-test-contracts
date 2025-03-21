import asyncio
from typing import List

from duckduckgo_search import DDGS

from api.v1.tools.helpers.jina import jina_parse
from api.v1.tools.schema import DuckDuckGoResponse, DuckDuckGoSearchResult
from config.prompts.summarise_prompt import (
    BEST_LINK_SELECTION_PROMPT,
    SUMMARISE_PROMPT,
)
from config.settings import LLM_SCAN_3
from core.db.repositories.search_results import SearchResults
from core.llm.send_prompt_to_llm import send_prompt_to_llm_async
from core.utils.errors import LLMError, SearchError
from core.utils.logger import logger

# Initialize global constants
_DEFAULT_REGION = "wt-wt"
MAX_DDGS_RESULTS = 3

# Semaphore to control concurrent link parsing
LINK_PARSE_SEMAPHORE = asyncio.Semaphore(5)
# Delay between link parsing in seconds
LINK_PARSE_DELAY = 0.2


async def perform_duckduckgo_search(query: str) -> str:
    """
    Perform a complete DuckDuckGo search workflow:
    1. Search for query
    2. Select best links
    3. Parse content from links
    4. Summarize content

    Args:
        query: Search query string

    Returns:
        str: Summarized content from search results

    Raises:
        SearchError: If there's an error during the search process
        LLMError: If there's an error with the LLM
    """
    try:
        # 1. Get raw search results
        results = await _search_raw(query)
        if len(results) == 0:
            logger.info(f"[DuckDuckGo] No results found, skipping this query: {query}")
            return ""

        # 2. Select best links using LLM
        best_links = await _select_best_links(query, results)
        if len(best_links) == 0:
            logger.info(f"[DuckDuckGo] No relevant links found, skipping this query: {query}")
            return ""

        logger.info(f"[DuckDuckGo] Gathering info from {len(best_links)} links")

        # 3. Parse and summarize content from links
        content = await _parse_search_results(best_links)
        return content

    except LLMError as e:
        logger.error(f"[DuckDuckGo] LLM error during search: {e.message}")
        # We'll pass this up to be handled in the service layer
        raise
    except Exception as e:
        logger.exception(f"[DuckDuckGo] Error in DuckDuckGo search pipeline: {e}")
        raise SearchError(
            message=f"Failed to perform search for query: {query}",
            details={"error": str(e), "query": query},
        )


async def _search_raw(query: str, max_results: int = MAX_DDGS_RESULTS) -> List[DuckDuckGoResponse]:
    """Perform raw DuckDuckGo search and return results."""
    try:
        results: List[DuckDuckGoResponse] = list(
            DDGS().text(
                keywords=query,
                region=_DEFAULT_REGION,
                max_results=max_results,
            )
        )
        return results
    except Exception as e:
        logger.exception(f"[DuckDuckGo] Error searching DuckDuckGo: {e}")
        raise SearchError(
            message="Failed to search DuckDuckGo", details={"error": str(e), "query": query}
        )


async def _select_best_links(query: str, results: List[DuckDuckGoResponse]) -> List[str]:
    """
    Select the best links from the search results.

    Raises:
        LLMError: If there's an error with the LLM processing
    """
    best_link_selection_prompt = BEST_LINK_SELECTION_PROMPT.format(query=query, links=results)
    response = await send_prompt_to_llm_async(
        model_type=LLM_SCAN_3,
        messages=best_link_selection_prompt,
        response_model=DuckDuckGoSearchResult,
    )
    return response.results


async def _parse_search_results(results: List[str]) -> str:
    """
    Summarize the results of a DuckDuckGo search by parsing content from result URLs in parallel.

    Args:
        results: DuckDuckGo search results containing URLs to parse

    Returns:
        str: Combined content from parsing all result URLs

    Raises:
        SearchError: If there's a critical error in parsing all results
    """
    try:
        # Extract links using list comprehension
        links = [result.href for result in results]
        logger.info(f"[DuckDuckGo] Processing {len(links)} links in parallel")

        async def process_single_link(link: str) -> str:
            """Process a single link with rate limiting"""
            async with LINK_PARSE_SEMAPHORE:
                # Checks for cache hit
                if await SearchResults.check_if_visited(link):
                    logger.info(f"[DuckDuckGo] Cache hit! skipping: {link}")
                    return await SearchResults.fetch_link_content(link)

                # Add a small delay to avoid rate limiting
                await asyncio.sleep(LINK_PARSE_DELAY)
                try:
                    logger.info(f"[DuckDuckGo] Parsing link: {link}")
                    content = await jina_parse(link)
                    if content == "":
                        logger.info(f"[DuckDuckGo] No content found, skipping this link: {link}")
                        return ""

                    summary = await _summarise_content(content)
                    # Store in cache for future use!
                    await SearchResults.add_content(link, summary)
                    return summary
                except Exception as e:
                    # We'll log but not fail the whole operation for a single link
                    logger.exception(f"[DuckDuckGo] Error parsing link {link}: {e}")
                    return ""

        # Process all links in parallel with controlled concurrency
        parsed_contents = await asyncio.gather(
            *[process_single_link(link) for link in links], return_exceptions=True
        )

        # Filter out exceptions and empty results
        valid_contents = []
        for i, content in enumerate(parsed_contents):
            if isinstance(content, Exception):
                logger.warning(f"[DuckDuckGo] Link {i + 1} processing failed: {str(content)}")
            elif content:  # Only add non-empty content
                valid_contents.append(content)

        return "".join(valid_contents)

    except Exception as e:
        logger.exception(f"[DuckDuckGo] Error parsing search results: {e}")
        raise SearchError(message="Failed to parse search results", details={"error": str(e)})


async def _summarise_content(content: str) -> str:
    """
    Summarize the parsed content of a webpage.

    Raises:
        LLMError: If the LLM fails to summarize the content
    """
    summarise_prompt = SUMMARISE_PROMPT.format(text=content)
    response = await send_prompt_to_llm_async(
        model_type=LLM_SCAN_3,
        messages=summarise_prompt,
    )
    return response
