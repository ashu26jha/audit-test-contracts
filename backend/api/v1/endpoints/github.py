from fastapi import APIRouter, Depends

from api.v1.helpers.repository_docs_helpers import get_json_docs
from api.v1.models.user import User
from api.v1.schemas.api_response_schema import SuccessResponse
from api.v1.services.auth_service import get_current_user
from api.v1.services.github_service import GitHubService

router = APIRouter()
github_service = GitHubService()


@router.get("/organizations", response_model=SuccessResponse)
async def get_organizations(current_user: User = Depends(get_current_user)):
    accessible_repos = await github_service.get_accessible_repositories(current_user.accessToken)
    orgs = []
    for repo in accessible_repos:
        orgs.append(
            {
                "login": repo["owner"],
                "type": "user",
            }
        )
    seen = set()
    orgs = [org for org in orgs if not (org["login"] in seen or seen.add(org["login"]))]
    return SuccessResponse(data=orgs)


@router.get("/repositories/{owner}", response_model=SuccessResponse)
async def get_repositories(owner: str, current_user: User = Depends(get_current_user)):
    accessible_repos = await github_service.get_accessible_repositories(current_user.accessToken)
    repos = []
    for repo in accessible_repos:
        if repo["owner"] == owner:
            repos.append(repo)
    return SuccessResponse(data=repos)


@router.get("/repository-branches/{owner}/{repo}", response_model=SuccessResponse)
async def get_repository_branches(
    owner: str,
    repo: str,
    current_user: User = Depends(get_current_user),
):
    branches = await github_service.get_repository_branches(current_user.accessToken, owner, repo)
    return SuccessResponse(data=branches)


@router.get("/repository-contents/{owner}/{repo}", response_model=SuccessResponse)
async def get_repository_contents(
    owner: str,
    repo: str,
    branch: str,
    path: str = "",
    current_user: User = Depends(get_current_user),
):
    """Get all Solidity files from the repository."""
    contents = await github_service.get_repository_contents(
        current_user.accessToken, owner, repo, branch, path
    )
    return SuccessResponse(data=contents)


@router.get("/repository-readme/{owner}/{repo}", response_model=SuccessResponse)
async def get_repository_readme(
    owner: str,
    repo: str,
    branch: str,
    path: str = "",
    current_user: User = Depends(get_current_user),
):
    """Get all README.md files from the repository."""
    contents = await github_service.get_repository_contents(
        current_user.accessToken, owner, repo, branch, path, file_type="readme"
    )
    return SuccessResponse(data=contents)


@router.get("/repository-info", response_model=SuccessResponse)
async def get_github_repo_info(
    repo_url: str,
    current_user: User = Depends(get_current_user),
):
    repo_info = await github_service.get_github_repo_info(current_user.accessToken, repo_url)
    return SuccessResponse(data=repo_info)


@router.get("/repository-docs/{owner}/{repo}", response_model=SuccessResponse)
async def get_repository_docs(
    owner: str,
    repo: str,
    current_user: User = Depends(get_current_user),
):
    """Get documentation for a specific repository."""
    # Construct the repository URL in the same format as stored
    repository_url = f"https://github.com/{owner}/{repo}"

    docs = await get_json_docs(repository_url, current_user.githubId)

    return SuccessResponse(
        data={
            "docs": docs,
            "repository_url": repository_url,
        }
    )


@router.get("/validate-repository", response_model=SuccessResponse)
async def validate_repository(
    repo_url: str,
    current_user: User = Depends(get_current_user),
):
    await github_service.validate_repository_access(current_user.accessToken, repo_url)
    return SuccessResponse(data={"accessible": True})
