import shutil
import tempfile
from typing import Union

from fastapi import APIRouter, HTTPException, status

from api.v1.github.helpers.clone_repo import clone_repo
from api.v1.utilities.ast_tree.schema import ASTTreeRequest, ASTTreeResponse
from api.v1.utilities.ast_tree.service import generate_ast_for_project
from core.schemas.api_response_schema import ErrorResponse, SuccessResponse
from core.utils.errors import CloneError, ContractError
from core.utils.logger import logger

router = APIRouter(tags=["utilities"])


@router.post(
    "/generate-ast-tree",
    response_model=Union[SuccessResponse[ASTTreeResponse], ErrorResponse],
)
async def get_ast_tree(request: ASTTreeRequest):
    """
    Generate a codebase tree for a contract.

    Args:
        request: ASTTreeRequest containing github_url and contracts_in_scope

    Returns:
        ASTTreeResponse with the generated AST tree
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

        # In route context, we should fail if no valid ASTs were generated
        if not ast_tree.contracts:
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail="Failed to generate AST for any contracts",
            )

        response = SuccessResponse(data=ASTTreeResponse(ast_tree=ast_tree))

        # Clean up temporary directory
        if temp_dir:
            shutil.rmtree(temp_dir)

        return response

    except CloneError as e:
        logger.error(f"[AST] Clone error: {e.message}")
        if temp_dir:
            shutil.rmtree(temp_dir)
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Failed to clone repository: {request.github_url}",
        )

    except ContractError as e:
        logger.error(f"[AST] Contract error: {e.message}")
        if temp_dir:
            shutil.rmtree(temp_dir)
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=e.message,
        )

    except Exception as e:
        logger.exception(f"[AST] Unexpected error: {e}")
        # Clean up temporary directory
        if temp_dir:
            shutil.rmtree(temp_dir)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="An unexpected error occurred while generating AST tree",
        )
