from typing import Dict, List

from duckduckgo_search import DDGS
from openai import OpenAI

from api.v1.tools.helpers.jina import parse
from api.v1.tools.schema import DuckDuckGoResponse, DuckDuckGoSearchResult
from config.prompts.summarise_prompt import SUMMARISE_PROMPT
from config.settings import OPENAI_API_KEY
from core.utils.logger import logger


class DuckDuckGoSearcher:
    def __init__(self):
        self.ddgs = DDGS()
        self.default_region = "wt-wt"
        self.default_safesearch = "moderate"

    async def search(self, query: str, max_results: int = 3) -> List[Dict[str, str]]:
        try:
            results = list(
                self.ddgs.text(
                    keywords=query,
                    region=self.default_region,
                    safesearch=self.default_safesearch,
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


def get_description() -> str:
    """
    Returns the description for the duckduckgo_search tool.
    """
    return """
        duckduckgo_search: Searches for information using DuckDuckGo and returns search results along with the webpage links. Good for indepth research. Exploring EIPs etc. Good for exploring docs and exploring the web.
        Sample use case scenario:
        Scenario 1: If a protocol uses Balancer V3 or Uniswap V3 or Curve V2, you can use this tool to search for vulnerabilities related improper integration of the protocol.
        Query: "Balancer V3 security considerations"
        Scenario 2: You can search about a particular library, contract or EIP.
        Query: "EIP-7777"
    """


async def perform_duckduckgo_search(query: str, max_results: int = 3) -> str:
    """
    Perform a DuckDuckGo search and return the summarized results.

    Args:
        query: Search query string
        max_results: Maximum number of results to return (default: 10)

    Returns:
        str: Summarized search results
    """
    try:
        results = await ddg_searcher.search(query, max_results)

        # Fix: Map the correct dictionary keys from DuckDuckGo results
        response = DuckDuckGoSearchResult(
            results=[
                DuckDuckGoResponse(
                    title=r.get("title", ""), href=r.get("href", ""), body=r.get("snippet", "")
                )
                for r in results
            ]
        )
        get_content = await parse_duckduckgo_search(response)
        summary = await summarize_duckduckgo_search(get_content)

        return summary

    except Exception as e:
        print(f"Error in DuckDuckGo search pipeline: {e}")
        return f"Failed to perform search: {str(e)}"


async def parse_duckduckgo_search(results: DuckDuckGoSearchResult) -> str:
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
        # Parse URLs with delay between requests to avoid rate limiting
        parsed_contents = []
        for link in links:
            try:
                content = await parse(link)
                logger.info(f"Parsed content: {content}")
                parsed_contents.append(content)
            except Exception as e:
                parsed_contents.append(e)

        # Filter out any failed parses and join successful ones
        valid_contents = [content for content in parsed_contents if isinstance(content, str)]
        return "".join(valid_contents)

    except Exception as e:
        print(f"Error parsing search results: {e}")
        return ""


async def summarize_duckduckgo_search(content: str) -> str:
    """
    Summarize the parsed content of a DuckDuckGo search.
    """
    openai = OpenAI(api_key=OPENAI_API_KEY)
    summarise_prompt = SUMMARISE_PROMPT.format(text=content)
    response = openai.chat.completions.create(
        model="o3-mini",
        messages=[
            {"role": "user", "content": summarise_prompt},
        ],
    )
    return response.choices[0].message.content
