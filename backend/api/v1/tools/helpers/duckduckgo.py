from typing import Dict, List

from duckduckgo_search import DDGS

from api.v1.tools.helpers.jina import parse
from config.prompts.summarise_prompt import (
    BEST_LINK_SELECTION_PROMPT,
    CLEAN_RESPONSE_PROMPT,
    SUMMARISE_PROMPT,
)
from config.settings import LLM_SCAN_3
from core.llm.send_prompt_to_llm import send_prompt_to_llm_async
from core.utils.logger import logger

MAX_DDGS_RESULTS = 10


class DuckDuckGoSearcher:
    def __init__(self):
        self.ddgs = DDGS()
        self.default_region = "wt-wt"
        self.default_safesearch = "moderate"

    async def search(self, query: str, max_results: int = MAX_DDGS_RESULTS) -> List[Dict[str, str]]:
        try:
            results = list(
                self.ddgs.text(
                    keywords=query,
                    region=self.default_region,
                    max_results=max_results,
                )
            )
            return results
        except Exception as e:
            print(f"Error searching DuckDuckGo: {e}")
            return []


ddg_searcher = DuckDuckGoSearcher()


async def search(query: str) -> List[Dict[str, str]]:
    return await ddg_searcher.search(query)


async def perform_duckduckgo_search(query: str) -> str:
    """
    Perform a DuckDuckGo search and return the summarized results.

    Args:
        query: Search query string
        max_results: Maximum number of results to return (default: 10)

    Returns:
        str: Summarized search results
    """
    try:
        from api.v1.tools.schema import DuckDuckGoSearchResult

        results = await ddg_searcher.search(query)
        if len(results) == 0:
            logger.info("No results found, skipping this query")
            return ""
        best_link_selection_prompt = BEST_LINK_SELECTION_PROMPT.format(query=query, links=results)
        response = await send_prompt_to_llm_async(
            model_type=LLM_SCAN_3,
            messages=best_link_selection_prompt,
            response_model=DuckDuckGoSearchResult,
        )

        if len(response.results) == 0:
            logger.info("No relevant links found, skipping this query")
            return ""

        logger.info(f"Rathering info from {len(response.results)} links")

        get_content = await parse_duckduckgo_search(response)

        return get_content

    except Exception as e:
        print(f"Error in DuckDuckGo search pipeline: {e}")
        return f"Failed to perform search: {str(e)}"


async def parse_duckduckgo_search(results) -> str:
    """
    Summarize the results of a DuckDuckGo search by parsing content from result URLs.

    Args:
        results: DuckDuckGo search results containing URLs to parse

    Returns:
        str: Combined content from parsing all result URLs
    """
    try:

        # Extract links using list comprehension
        links = [result.href for result in results.results]
        logger.info(f"Links: {links}")
        parsed_contents = []
        for link in links:
            try:
                logger.info(f"Parsing link: {link}")
                content = await parse(link)
                if content == "":
                    logger.info("No content found, skipping this link")
                    continue
                summary = await summarise_content(content)
                parsed_contents.append(summary)
            except Exception as e:
                parsed_contents.append(e)

        # Filter out any failed parses and join successful ones
        valid_contents = [content for content in parsed_contents if isinstance(content, str)]
        return "".join(valid_contents)

    except Exception as e:
        print(f"Error parsing search results: {e}")
        return ""


async def summarise_content(content: str) -> str:
    """
    Summarize the parsed content of a webpage.
    """
    summarise_prompt = SUMMARISE_PROMPT.format(text=content)
    response = await send_prompt_to_llm_async(
        model_type=LLM_SCAN_3,
        messages=summarise_prompt,
    )
    return response


async def clean_response(summary: str, ast: str, docs: str) -> str:
    """
    Clean the response from the summarise_content function.
    """
    clean_response_prompt = CLEAN_RESPONSE_PROMPT.format(summary=summary, ast=ast, docs=docs)
    response = await send_prompt_to_llm_async(
        model_type=LLM_SCAN_3,
        messages=clean_response_prompt,
    )
    return response
