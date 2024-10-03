from api.v1.models.user import User
from api.v1.schemas.api_response_schema import SuccessResponse
from api.v1.services.auth_service import get_current_user
from api.v1.services.github_service import GitHubService
from common import logger
from fastapi import APIRouter, Depends, HTTPException, Query

router = APIRouter()
github_service = GitHubService()


# @router.get("/organizations")
# async def get_organizations(current_user: User = Depends(get_current_user)):
#     return await github_service.get_user_organizations(current_user.accessToken)


# @router.get("/repositories/{org}")
# async def get_repositories(org: str, current_user: User = Depends(get_current_user)):
#     return await github_service.get_organization_repositories(current_user.accessToken, org)


@router.get("/organizations", response_model=SuccessResponse)
async def get_organizations(current_user: User = Depends(get_current_user)):
    orgs = await github_service.get_user_organizations_and_personal(current_user.accessToken)
    return SuccessResponse(data=orgs)


@router.get("/repositories/{owner}", response_model=SuccessResponse)
async def get_repositories(
    owner: str, owner_type: str, current_user: User = Depends(get_current_user)
):
    repos = await github_service.get_repositories(current_user.accessToken, owner, owner_type)
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
    contents = await github_service.get_repository_contents(
        current_user.accessToken, owner, repo, branch, path
    )
    return SuccessResponse(data=contents)


@router.get("/repository-info", response_model=SuccessResponse)
async def get_github_repo_info(
    repo_url: str,
    current_user: User = Depends(get_current_user),
):
    repo_info = await github_service.get_github_repo_info(current_user.accessToken, repo_url)
    return SuccessResponse(data=repo_info)


@router.get("/validate-repo-url", response_model=SuccessResponse)
async def validate_repo_url(
    repo_url: str = Query(...),
    current_user: User = Depends(get_current_user),
):
    try:
        repo_info = await github_service.check_repository_access(current_user.accessToken, repo_url)
        return SuccessResponse(
            data={
                "repo_name": repo_info.get("name"),
                "owner": repo_info.get("owner", {}).get("login"),
                "default_branch": repo_info.get("default_branch", "main"),
                "repo_url": repo_url,
            }
        )
    except HTTPException as e:
        raise e
    except Exception as e:
        logger.error(f"Error validating repository URL: {e}")
        raise HTTPException(status_code=500, detail="Internal server error")
