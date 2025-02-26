from .helpers.duckduckgo import perform_duckduckgo_search as ddg_search
from .helpers.jina import parse as jina_parse
from .helpers.perplexity import search as perplexity_search


async def duckduckgo_search_service(query: str) -> str:
    return await ddg_search(query)


async def jina_parse_service(url: str) -> str:
    return await jina_parse(url)


async def perplexity_search_service(query: str) -> str:
    return await perplexity_search(query)
