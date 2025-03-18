from typing import List, Union

from fastapi import APIRouter, Depends, HTTPException, Query

from api.v1.auth.helpers.dependencies import get_current_user
from api.v1.common.docs_helpers import get_json_docs
from api.v1.github.schema import (
    FileType,
    GitHubBranch,
    GitHubFileContent,
    GitHubOrganizationResponse,
    GitHubRepoInfo,
    GitHubRepository,
    GitHubRepositoryDocs,
    GitHubRepositoryValidation,
    QAResponse,
)
from core.models.user import User
from core.schemas.api_response_schema import ErrorResponse, SuccessResponse
from core.utils.errors import AuthError, HTTPClientError, RepositoryError, ValidationError

from .service import GitHubService

github_service = GitHubService()

router = APIRouter(prefix="/github", tags=["github"])


@router.get(
    "/organizations",
    response_model=Union[SuccessResponse[List[GitHubOrganizationResponse]], ErrorResponse],
    description="Get list of unique organizations and users the current user has access to",
)
async def get_organizations(current_user: User = Depends(get_current_user)):
    """
    Get unique list of organizations and users the current user has access to.

    Returns:
        List of unique organizations with their type and login name
    """
    try:
        # Get installations directly from GitHub API
        installations = await github_service.client.get_installations(current_user.accessToken)

        # Create a mapping of login to organization data
        organizations_map = {
            current_user.username: GitHubOrganizationResponse(
                login=current_user.username,
                type="User",
                avatar_url=current_user.avatarUrl,
                url=f"https://github.com/{current_user.username}",
            )
        }

        # Add organizations from installations
        for installation in installations:
            if "account" in installation and "login" in installation["account"]:
                login = installation["account"]["login"]
                if login != current_user.username:  # Skip if already added
                    organizations_map[login] = GitHubOrganizationResponse(
                        login=login,
                        type=installation["account"].get("type", "User"),
                        avatar_url=installation["account"].get("avatar_url"),
                        url=installation["account"].get("html_url"),
                    )

        # Add any missing organizations from repositories
        accessible_repos = await github_service.get_accessible_repositories(
            current_user.accessToken
        )
        for repo in accessible_repos:
            owner = repo["owner"]
            if owner not in organizations_map:
                organizations_map[owner] = GitHubOrganizationResponse(
                    login=owner,
                    type="User",  # Default to User
                )

        return SuccessResponse(data=list(organizations_map.values()))
    except AuthError as e:
        raise HTTPException(status_code=401, detail=e.message)
    except RepositoryError as e:
        raise HTTPException(status_code=404, detail=e.message)
    except ValidationError as e:
        raise HTTPException(status_code=422, detail=e.message)
    except HTTPClientError as e:
        raise HTTPException(status_code=503, detail=e.message)


@router.get(
    "/repositories/{owner}",
    response_model=Union[SuccessResponse[List[GitHubRepository]], ErrorResponse],
    description="Get list of repositories for a specific owner",
)
async def get_repositories(
    owner: str,
    current_user: User = Depends(get_current_user),
):
    """
    Get list of repositories for a specific owner that the current user has access to.

    Args:
        owner: GitHub username or organization name

    Returns:
        List of repositories with their details
    """
    try:
        accessible_repos = await github_service.get_accessible_repositories(
            current_user.accessToken
        )
        repos = [repo for repo in accessible_repos if repo["owner"] == owner]
        return SuccessResponse(data=repos)
    except AuthError as e:
        raise HTTPException(status_code=401, detail=e.message)
    except RepositoryError as e:
        raise HTTPException(status_code=404, detail=e.message)
    except ValidationError as e:
        raise HTTPException(status_code=422, detail=e.message)
    except HTTPClientError as e:
        raise HTTPException(status_code=503, detail=e.message)


@router.get(
    "/repository-branches/{owner}/{repo}",
    response_model=Union[SuccessResponse[List[GitHubBranch]], ErrorResponse],
    description="Get list of branches for a specific repository",
)
async def get_repository_branches(
    owner: str,
    repo: str,
    current_user: User = Depends(get_current_user),
):
    """
    Get list of branches for a specific repository.

    Args:
        owner: Repository owner
        repo: Repository name

    Returns:
        List of branches with their details
    """
    try:
        branches = await github_service.get_repository_branches(
            current_user.accessToken, owner, repo
        )
        return SuccessResponse(data=branches)
    except AuthError as e:
        raise HTTPException(status_code=401, detail=e.message)
    except RepositoryError as e:
        raise HTTPException(status_code=404, detail=e.message)
    except ValidationError as e:
        raise HTTPException(status_code=422, detail=e.message)
    except HTTPClientError as e:
        raise HTTPException(status_code=503, detail=e.message)


@router.get(
    "/repository-contents/{owner}/{repo}",
    response_model=Union[SuccessResponse[List[GitHubFileContent]], ErrorResponse],
    description="Get all Solidity files from the repository",
)
async def get_repository_contents(
    owner: str,
    repo: str,
    branch: str,
    path: str = Query("", description="Optional path within repository"),
    file_type: FileType = Query(FileType.SOLIDITY, description="Type of files to fetch"),
    current_user: User = Depends(get_current_user),
):
    """
    Get repository contents filtered by file type.

    Args:
        owner: Repository owner
        repo: Repository name
        branch: Branch name
        path: Optional path within repository
        file_type: Type of files to fetch (sol or readme)

    Returns:
        List of files with their contents and analysis
    """
    try:
        contents = await github_service.get_repository_contents(
            current_user.accessToken,
            owner,
            repo,
            branch,
            path,
            file_type=file_type,
        )
        return SuccessResponse(data=contents)
    except AuthError as e:
        raise HTTPException(status_code=401, detail=e.message)
    except RepositoryError as e:
        raise HTTPException(status_code=404, detail=e.message)
    except ValidationError as e:
        raise HTTPException(status_code=422, detail=e.message)
    except HTTPClientError as e:
        raise HTTPException(status_code=503, detail=e.message)


@router.get(
    "/repository-readme/{owner}/{repo}",
    response_model=Union[SuccessResponse[List[GitHubFileContent]], ErrorResponse],
    description="Get all README.md files from the repository",
)
async def get_repository_readme(
    owner: str,
    repo: str,
    branch: str,
    path: str = Query("", description="Optional path within repository"),
    current_user: User = Depends(get_current_user),
):
    """
    Get all README.md files from the repository.

    Args:
        owner: Repository owner
        repo: Repository name
        branch: Branch name
        path: Optional path within repository

    Returns:
        List of README files with their contents and analysis
    """
    try:
        contents = await github_service.get_repository_contents(
            current_user.accessToken,
            owner,
            repo,
            branch,
            path,
            file_type=FileType.README,
        )
        return SuccessResponse(data=contents)
    except AuthError as e:
        raise HTTPException(status_code=401, detail=e.message)
    except RepositoryError as e:
        raise HTTPException(status_code=404, detail=e.message)
    except ValidationError as e:
        raise HTTPException(status_code=422, detail=e.message)
    except HTTPClientError as e:
        raise HTTPException(status_code=503, detail=e.message)


@router.get(
    "/repository-info",
    response_model=Union[SuccessResponse[GitHubRepoInfo], ErrorResponse],
    description="Get repository information",
)
async def get_github_repo_info(
    repo_url: str = Query(..., description="Full GitHub repository URL"),
    current_user: User = Depends(get_current_user),
):
    """
    Get detailed information about a repository.

    Args:
        repo_url: Full GitHub repository URL

    Returns:
        Repository information including name, owner, and default branch
    """
    try:
        repo_info = await github_service.get_github_repo_info(current_user.accessToken, repo_url)
        return SuccessResponse(data=repo_info)
    except AuthError as e:
        raise HTTPException(status_code=401, detail=e.message)
    except RepositoryError as e:
        raise HTTPException(status_code=404, detail=e.message)
    except ValidationError as e:
        raise HTTPException(status_code=422, detail=e.message)
    except HTTPClientError as e:
        raise HTTPException(status_code=503, detail=e.message)


@router.get(
    "/repository-docs/{owner}/{repo}",
    response_model=Union[SuccessResponse[GitHubRepositoryDocs], ErrorResponse],
    description="Get documentation for a specific repository",
)
async def get_repository_docs(
    owner: str,
    repo: str,
    current_user: User = Depends(get_current_user),
):
    """
    Get documentation for a specific repository.

    Args:
        owner: Repository owner
        repo: Repository name

    Returns:
        Repository documentation and URL
    """
    try:
        # Construct the repository URL in the same format as stored
        repository_url = f"https://github.com/{owner}/{repo}"
        docs = await get_json_docs(repository_url, current_user.githubId)

        return SuccessResponse(
            data=GitHubRepositoryDocs(
                docs=docs or QAResponse(readme=[], qa={}),
                repository_url=repository_url,
            )
        )
    except AuthError as e:
        raise HTTPException(status_code=401, detail=e.message)
    except RepositoryError as e:
        raise HTTPException(status_code=404, detail=e.message)
    except ValidationError as e:
        raise HTTPException(status_code=422, detail=e.message)
    except HTTPClientError as e:
        raise HTTPException(status_code=503, detail=e.message)


@router.get(
    "/validate-repository",
    response_model=Union[SuccessResponse[GitHubRepositoryValidation], ErrorResponse],
    description="Validate repository access",
)
async def validate_repository(
    repo_url: str = Query(..., description="Full GitHub repository URL"),
    current_user: User = Depends(get_current_user),
):
    """
    Validate if a repository is accessible to the current user.

    Args:
        repo_url: Full GitHub repository URL

    Returns:
        Object indicating if the repository is accessible

    Raises:
        HTTPException: If repository is private or inaccessible
    """
    try:
        await github_service.validate_repository_access(current_user.accessToken, repo_url)
        return SuccessResponse(data=GitHubRepositoryValidation(accessible=True))
    except AuthError as e:
        raise HTTPException(status_code=401, detail=e.message)
    except RepositoryError as e:
        raise HTTPException(status_code=404, detail=e.message)
    except ValidationError as e:
        raise HTTPException(status_code=422, detail=e.message)
    except HTTPClientError as e:
        raise HTTPException(status_code=503, detail=e.message)
