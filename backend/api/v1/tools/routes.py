import tempfile

from fastapi import APIRouter, Depends

from api.v1.auth.helpers.dependencies import get_api_key
from api.v1.github.helpers.clone_repo import clone_repo
from api.v1.utilities.ast_tree.service import generate_ast_for_project

# Import schemas for each tool
from .schema import (
    BuildQueriesRequest,
    JinaParseRequest,
    JinaParseResult,
)

# Import helper service functions from the new helper folder
from .service import (
    build_and_execute_queries_service,
    jina_parse_service,
)

router = APIRouter(tags=["Tools"], prefix="/tools")


@router.post("/jina-parse", response_model=JinaParseResult)
async def jina_parse_route(request: JinaParseRequest):
    response = await jina_parse_service(request.url)
    return JinaParseResult(response=response)


@router.post("/build-queries", dependencies=[Depends(get_api_key)])
async def build_queries_route(request: BuildQueriesRequest):
    temp_dir = None

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
    response = await build_and_execute_queries_service(
        contracts=request.contracts,
        num_queries=request.num_queries,
        ast_tree=ast_tree,
    )
    return response
