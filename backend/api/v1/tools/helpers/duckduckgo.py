from typing import List

from duckduckgo_search import DDGS

from api.v1.tools.helpers.jina import jina_parse
from api.v1.tools.schema import DuckDuckGoResponse, DuckDuckGoSearchResult
from config.prompts.summarise_prompt import (
    BEST_LINK_SELECTION_PROMPT,
    SUMMARISE_PROMPT,
)
from config.settings import LLM_SCAN_3
from core.llm.send_prompt_to_llm import send_prompt_to_llm_async
from core.utils.logger import logger

# Initialize global constants
_DEFAULT_REGION = "wt-wt"
MAX_DDGS_RESULTS = 3


async def perform_duckduckgo_search(query: str) -> str:
    """
    Perform a complete DuckDuckGo search workflow:
    1. Search for query
    2. Select best links
    3. Parse content from links
    4. Summarize content
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

    except Exception as e:
        logger.exception(f"[DuckDuckGo] Error in DuckDuckGo search pipeline: {e}")
        return f"Failed to perform search: {str(e)}"


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
        return []


async def _select_best_links(query: str, results: List[DuckDuckGoResponse]) -> List[str]:
    """
    Select the best links from the search results.
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
    Summarize the results of a DuckDuckGo search by parsing content from result URLs.

    Args:
        results: DuckDuckGo search results containing URLs to parse

    Returns:
        str: Combined content from parsing all result URLs
    """
    try:

        # Extract links using list comprehension
        links = [result.href for result in results]
        logger.info(f"[DuckDuckGo] Links: {links}")
        parsed_contents = []

        for link in links:
            try:
                logger.info(f"[DuckDuckGo] Parsing link: {link}")
                content = await jina_parse(link)
                if content == "":
                    logger.info(f"[DuckDuckGo] No content found, skipping this link: {link}")
                    continue

                summary = await _summarise_content(content)
                parsed_contents.append(summary)
            except Exception as e:
                logger.exception(f"[DuckDuckGo] Error parsing link {link}: {e}")

        # Filter out any failed parses and join successful ones
        valid_contents = [content for content in parsed_contents if isinstance(content, str)]
        return "".join(valid_contents)

    except Exception as e:
        logger.exception(f"[DuckDuckGo] Error parsing search results: {e}")
        return ""


async def _summarise_content(content: str) -> str:
    """
    Summarize the parsed content of a webpage.
    """
    summarise_prompt = SUMMARISE_PROMPT.format(text=content)
    response = await send_prompt_to_llm_async(
        model_type=LLM_SCAN_3,
        messages=summarise_prompt,
    )
    return response
