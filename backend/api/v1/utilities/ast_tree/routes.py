import shutil
import tempfile
from typing import Union

from fastapi import APIRouter, status

from api.v1.github.helpers.clone_repo import clone_repo
from api.v1.utilities.ast_tree.schema import ASTTreeRequest, ASTTreeResponse
from api.v1.utilities.ast_tree.service import generate_ast_for_project
from core.schemas.api_response_schema import ErrorResponse, SuccessResponse

router = APIRouter(tags=["utilities"])


@router.post(
    "/generate-ast-tree",
    response_model=Union[SuccessResponse[ASTTreeResponse], ErrorResponse],
)
async def get_ast_tree(request: ASTTreeRequest):
    """
    Generate a codebase tree for a contract.

    Args:
        request: CodebaseTreeRequest

    Returns:
        CodebaseTreeResponse
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

        # Check if any contracts were successfully processed
        if not ast_tree.contracts:
            return ErrorResponse(
                code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                message="Failed to generate AST for any contracts",
                details="All contracts failed during AST generation. Check logs for details.",
            )

        # Delete temporary directory
        if temp_dir:
            shutil.rmtree(temp_dir)

        return SuccessResponse(data=ASTTreeResponse(ast_tree=ast_tree))
    except Exception as e:
        # Delete temporary directory
        if temp_dir:
            shutil.rmtree(temp_dir)
        return ErrorResponse(
            code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            message="An error occurred while generating ast tree",
            details=str(e),
        )
