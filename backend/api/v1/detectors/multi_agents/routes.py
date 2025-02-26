import shutil
import tempfile
from typing import Union

from fastapi import APIRouter, HTTPException

from api.v1.github.helpers.clone_repo import clone_repo
from api.v1.utilities.ast_tree.service import generate_ast_for_project
from core.schemas.api_response_schema import ErrorResponse, SuccessResponse

from .schema import MultiAgentRequest, MultiAgentResponse
from .service import run_multi_agent

router = APIRouter(prefix="/multi-agents", tags=["Multi-Agents"])


@router.post(
    "/launch",
    response_model=Union[SuccessResponse[MultiAgentResponse], ErrorResponse],
)
async def launch_multi_agent(request: MultiAgentRequest):
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

        # Run multi-agent analysis
        results = await run_multi_agent(
            contracts_in_scope=request.contracts_in_scope,
            ast_tree=ast_tree,
            project_dir=repo_dir,
        )

        # Delete temporary directory
        if temp_dir:
            shutil.rmtree(temp_dir)

        return SuccessResponse(data=results)
    except Exception as e:
        # Delete temporary directory
        if temp_dir:
            shutil.rmtree(temp_dir)
        raise HTTPException(status_code=500, detail=f"Multi-agent analysis failed: {str(e)}")
