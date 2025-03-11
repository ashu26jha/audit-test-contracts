import os
import tempfile
from typing import Union

from fastapi import APIRouter, Depends, HTTPException

from api.v1.auth.helpers.dependencies import get_api_key
from api.v1.github.helpers.clone_repo import clone_repo
from api.v1.utilities.ast_tree.service import generate_ast_for_project
from core.schemas.api_response_schema import ErrorResponse, SuccessResponse
from core.utils import logger

from .schema import (
    BuildQueriesRequest,
    JinaParseRequest,
    JinaParseResult,
)
from .service import (
    duckduckgo_search_service,
    jina_parse_service,
    query_and_search_service,
)

router = APIRouter(prefix="/tools", tags=["tools"])


@router.get(
    "/ddg-search/{query}",
    response_model=Union[SuccessResponse[str], ErrorResponse],
    description="Search a given query using DuckDuckGo",
)
async def ddg_search_route(query: str):
    response = await duckduckgo_search_service(query)
    return SuccessResponse(data=response)


@router.post(
    "/jina-parse",
    response_model=Union[SuccessResponse[JinaParseResult], ErrorResponse],
    description="Parse a given URL using Jina",
)
async def jina_parse_route(request: JinaParseRequest):
    response = await jina_parse_service(request.url)
    return SuccessResponse(data=JinaParseResult(response=response))


@router.post(
    "/build-queries",
    dependencies=[Depends(get_api_key)],
    response_model=Union[SuccessResponse[str], ErrorResponse],
    description="Build and execute queries for a given repository and contracts",
)
async def build_queries_route(request: BuildQueriesRequest):
    temp_dir = None

    try:
        # Create temporary directory
        temp_dir = tempfile.mkdtemp()

        # Clone repository
        repo_dir = await clone_repo(
            request.github_url,
            temp_dir,
            "test_access_token",
            "main",
        )

        # Generate AST tree
        ast_tree = await generate_ast_for_project(repo_dir, request.contracts_in_scope)

        # Build and execute queries
        response = await query_and_search_service(
            contracts=request.contracts,
            num_queries=request.num_queries,
            ast_tree=ast_tree,
        )

        return SuccessResponse(data=response)
    except Exception as e:
        logger.exception(f"[Tools] Error in build_queries_route: {e}")
        raise HTTPException(status_code=500, detail=str(e))
    finally:
        # Clean up temporary directory
        if temp_dir and os.path.exists(temp_dir):
            import shutil

            shutil.rmtree(temp_dir)
