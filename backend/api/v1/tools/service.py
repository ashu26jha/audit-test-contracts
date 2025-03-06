from typing import List

from api.v1.detectors.multi_agents.schema import EntryPoint
from core.utils import logger

from .helpers.duckduckgo import perform_duckduckgo_search as ddg_search
from .helpers.execute_queries import build_and_execute_queries
from .helpers.jina import parse as jina_parse


async def duckduckgo_search_service(query: str) -> str:
    return await ddg_search(query)


async def jina_parse_service(url: str) -> str:
    return await jina_parse(url)


async def build_and_execute_queries_service(
    contracts: str,
    num_queries: int,
    docs: str = None,
    entry_point: EntryPoint = None,
    ast_tree: str = None,
) -> List[str]:
    try:
        return await build_and_execute_queries(contracts, docs, num_queries, entry_point, ast_tree)
    except Exception as e:
        logger.error(f"[Tools] Error building and executing queries: {e}")
        return None
