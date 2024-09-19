from api.v1.models.user import User
from api.v1.services.auth_service import get_current_user
from api.v1.services.github_service import GitHubService
from fastapi import APIRouter, Depends

router = APIRouter()
github_service = GitHubService()


# @router.get("/organizations")
# async def get_organizations(current_user: User = Depends(get_current_user)):
#     return await github_service.get_user_organizations(current_user.accessToken)


# @router.get("/repositories/{org}")
# async def get_repositories(org: str, current_user: User = Depends(get_current_user)):
#     return await github_service.get_organization_repositories(current_user.accessToken, org)


@router.get("/organizations")
async def get_organizations(current_user: User = Depends(get_current_user)):
    return await github_service.get_user_organizations_and_personal(current_user.accessToken)


@router.get("/repositories/{owner}")
async def get_repositories(
    owner: str, owner_type: str, current_user: User = Depends(get_current_user)
):
    return await github_service.get_repositories(current_user.accessToken, owner, owner_type)


@router.get("/repository-contents/{owner}/{repo}")
async def get_repository_contents(
    owner: str,
    repo: str,
    path: str = "",
    current_user: User = Depends(get_current_user),
):
    return await github_service.get_repository_contents(current_user.accessToken, owner, repo, path)
