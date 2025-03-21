from langfuse.decorators import observe

from api.v1.detectors.multi_agents.schema import EntryPoint
from api.v1.tools.helpers.jina import jina_parse
from api.v1.utilities.ast_tree.schema import ProjectAST
from core.utils.errors import LLMError, QueryGenerationError, SearchError
from core.utils.logger import logger

from .helpers.duckduckgo import perform_duckduckgo_search
from .helpers.queries import build_queries, execute_queries


async def duckduckgo_search_service(query: str) -> str:
    """
    Service to perform a DuckDuckGo search

    Args:
        query: Search query

    Returns:
        str: Search results

    Raises:
        SearchError: If search fails
    """
    # This service propagates errors for API routes to handle
    return await perform_duckduckgo_search(query)


async def jina_parse_service(url: str) -> str:
    """
    Service to parse a URL using Jina

    Args:
        url: URL to parse

    Returns:
        str: Parsed content

    Raises:
        ParsingError: If parsing fails
    """
    # This service propagates errors for API routes to handle
    return await jina_parse(url)


@observe(name="query_and_search_service")
async def query_and_search_service(
    contracts: str,
    num_queries: int,
    docs: str = None,
    ast_tree: ProjectAST = None,
    entry_point: EntryPoint = None,
) -> str:
    """
    Builds queries and executes them to get the summarised results.
    When used in a background task, this service fails silently.

    Args:
        contracts: str - The full smart contracts flattened to build queries for
        num_queries: int - The number of queries to build
        docs: str - The documentation of the protocol to build queries for
        entry_point: EntryPoint - The entry point of the protocol to build queries for
        ast_tree: str - The AST tree of the smart contracts

    Returns:
        str: Summarised results or empty string on failure
    """
    try:
        queries = await build_queries(contracts, docs, num_queries, entry_point)
        return await execute_queries(queries=queries, docs=docs, ast_tree=ast_tree)
    except (QueryGenerationError, SearchError, LLMError) as e:
        # For both route and background tasks, log the error and return empty string
        logger.error(f"[Tools] Error in query_and_search_service: {e.message}")
        return ""
    except Exception as e:
        logger.error(f"[Tools] Error building and executing queries: {e}")
        return ""
