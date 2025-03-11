from langfuse.decorators import observe

from api.v1.detectors.multi_agents.schema import EntryPoint
from api.v1.tools.helpers.jina import jina_parse
from core.utils.logger import logger

from .helpers.duckduckgo import perform_duckduckgo_search
from .helpers.queries import build_queries, execute_queries


async def duckduckgo_search_service(query: str) -> str:
    return await perform_duckduckgo_search(query)


async def jina_parse_service(url: str) -> str:
    return await jina_parse(url)


@observe(name="query_and_search_service")
async def query_and_search_service(
    contracts: str,
    num_queries: int,
    docs: str = None,
    ast_tree: str = None,
    entry_point: EntryPoint = None,
) -> str:
    """
    Builds queries and executes them to get the summarised results.

    Args:
        contracts: str - The full smart contracts flattened to build queries for
        num_queries: int - The number of queries to build
        docs: str - The documentation of the protocol to build queries for
        entry_point: EntryPoint - The entry point of the protocol to build queries for
        ast_tree: str - The AST tree of the smart contracts

    Returns:
        str: Summarised results
    """

    try:
        queries = await build_queries(contracts, docs, num_queries, entry_point)
        return await execute_queries(queries, ast_tree, docs)
    except Exception as e:
        logger.error(f"[Tools] Error building and executing queries: {e}")
        return ""
