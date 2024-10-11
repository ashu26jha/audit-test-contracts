import httpx
from fastapi import APIRouter, Depends, HTTPException
from fastapi.responses import RedirectResponse
from fastapi.security import OAuth2AuthorizationCodeBearer
from starlette.requests import Request

from api.v1.models.user import User
from api.v1.schemas.user_schema import UserResponse
from api.v1.services.auth_service import create_access_token, get_current_user
from api.v1.services.github_service import GitHubService
from config import settings

router = APIRouter()

oauth2_scheme = OAuth2AuthorizationCodeBearer(
    authorizationUrl="https://github.com/login/oauth/authorize",
    tokenUrl="https://github.com/login/oauth/access_token",
)

github_service = GitHubService()


@router.get("/github-login")
async def github_login():
    return RedirectResponse(
        f"https://github.com/login/oauth/authorize?client_id={settings.GITHUB_CLIENT_ID}&scope=user:email read:org repo"
    )


@router.get("/github-callback")
async def github_callback(code: str, request: Request):
    # Exchange code for access token
    token_url = "https://github.com/login/oauth/access_token"
    headers = {"Accept": "application/json"}
    data = {
        "client_id": settings.GITHUB_CLIENT_ID,
        "client_secret": settings.GITHUB_CLIENT_SECRET,
        "code": code,
    }

    async with httpx.AsyncClient() as client:
        response = await client.post(token_url, headers=headers, data=data)

    if response.status_code != 200:
        raise HTTPException(status_code=400, detail="Could not retrieve token")

    token_data = response.json()
    access_token = token_data.get("access_token")

    if not access_token:
        raise HTTPException(status_code=400, detail="Invalid token response")

    # Get user info from GitHub
    user_data = await github_service.get_user_data(access_token)

    # Create or update user in database
    user = await User.find_one({"githubId": str(user_data["id"])})
    if not user:
        user = User(
            githubId=str(user_data["id"]),
            username=user_data["login"],
            email=user_data["email"],
            accessToken=access_token,
            avatarUrl=user_data["avatar_url"],
            name=user_data["name"],
        )
        await user.create()
    else:
        user.accessToken = access_token
        await user.save()

    # Create JWT token
    jwt_token = create_access_token(data={"sub": str(user.id)})

    # Redirect to frontend with token
    return RedirectResponse(f"{settings.FRONTEND_URL}/login-success?token={jwt_token}")


@router.post("/logout")
async def logout(current_user: User = Depends(get_current_user)):
    # In a real-world scenario, you might want to invalidate the token or perform other cleanup
    return {"message": "Successfully logged out"}


@router.get("/me", response_model=UserResponse)
async def read_users_me(current_user: User = Depends(get_current_user)):
    return UserResponse(**current_user.model_dump())
