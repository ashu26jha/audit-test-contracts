import os
import shutil
import tempfile
from typing import Union

from fastapi import APIRouter, Depends, HTTPException, status

from api.v1.auth.helpers.dependencies import get_api_key
from api.v1.github.helpers.clone_repo import clone_repo
from api.v1.utilities.ast_tree.service import generate_ast_for_project
from core.schemas.api_response_schema import ErrorResponse, SuccessResponse
from core.utils.errors import (
    CloneError,
    LLMError,
    ParsingError,
    SearchError,
)
from core.utils.logger import logger

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

UNKNOWN_ERROR_MESSAGE = "An unexpected error occurred"


@router.get(
    "/ddg-search/{query}",
    response_model=Union[SuccessResponse[str], ErrorResponse],
    description="Search a given query using DuckDuckGo",
)
async def ddg_search_route(query: str):
    """
    Search a given query using DuckDuckGo.
    """
    try:
        response = await duckduckgo_search_service(query)

        # If the service returned an empty string, it means it failed
        if not response:
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail="Failed to retrieve search results",
            )

        return SuccessResponse(data=response)
    except SearchError as e:
        logger.error(f"[Tools] Search error: {e.message}")
        raise HTTPException(
            status_code=status.HTTP_502_BAD_GATEWAY, detail="Failed to perform search"
        )
    except LLMError as e:
        logger.error(f"[Tools] LLM error in search: {e.message}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Error processing search results",
        )
    except Exception as e:
        logger.exception(f"[Tools] Unexpected error in search: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail=UNKNOWN_ERROR_MESSAGE
        )


@router.post(
    "/jina-parse",
    response_model=Union[SuccessResponse[JinaParseResult], ErrorResponse],
    description="Parse a given URL using Jina",
)
async def jina_parse_route(request: JinaParseRequest):
    """
    Parse a given URL using Jina.
    """
    try:
        response = await jina_parse_service(request.url)

        # If the service returned an empty string, it means it failed
        if not response:
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="Failed to parse URL"
            )

        return SuccessResponse(data=JinaParseResult(response=response))
    except ParsingError as e:
        logger.error(f"[Tools] Parsing error: {e.message}")
        raise HTTPException(
            status_code=status.HTTP_502_BAD_GATEWAY, detail=f"Failed to parse URL: {request.url}"
        )
    except Exception as e:
        logger.exception(f"[Tools] Unexpected error parsing URL: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail=UNKNOWN_ERROR_MESSAGE
        )


@router.post(
    "/build-queries",
    dependencies=[Depends(get_api_key)],
    response_model=Union[SuccessResponse[str], ErrorResponse],
    description="Build and execute queries for a given repository and contracts",
)
async def build_queries_route(request: BuildQueriesRequest):
    """
    Build and execute queries for a given repository and contracts.
    """
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

        # Check if AST generation was successful
        if not ast_tree.contracts:
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail="Failed to generate AST for any contracts",
            )

        # Build and execute queries
        response = await query_and_search_service(
            contracts=request.contracts,
            num_queries=request.num_queries,
            ast_tree=ast_tree,
        )

        # If the service returned an empty string, it means it failed
        if not response:
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail="Failed to process queries and search",
            )

        return SuccessResponse(data=response)
    except CloneError as e:
        logger.error(f"[Tools] Clone error: {e.message}")
        if temp_dir:
            shutil.rmtree(temp_dir)
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Failed to clone repository: {request.github_url}",
        )
    except Exception as e:
        logger.exception(f"[Tools] Error in build_queries_route: {e}")
        # Clean up temporary directory
        if temp_dir:
            shutil.rmtree(temp_dir)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail=UNKNOWN_ERROR_MESSAGE
        )
    finally:
        # Clean up temporary directory
        if temp_dir and os.path.exists(temp_dir):
            shutil.rmtree(temp_dir)
