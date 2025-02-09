import httpx
from fastapi import HTTPException

from config import settings
from config.settings import GITHUB_API_URL
from core.db.repositories.user import UserRepository
from core.models.user import User


async def validate_github_token(user: User) -> User:
    """Validate a GitHub access token by making a simple API call."""
    async with httpx.AsyncClient() as client:
        response = await client.get(
            f"{GITHUB_API_URL}/user",
            headers={
                "Authorization": f"token {user.accessToken}",
                "Accept": "application/vnd.github.v3+json",
            },
        )

        # If access token is expired, refresh the token and return the updated user
        if response.status_code == 401:
            updated_user = await refresh_access_token(user)
            return updated_user

        if response.status_code != 200:
            raise HTTPException(status_code=response.status_code, detail="GitHub API error")

        return user


async def refresh_access_token(user: User) -> User:
    """Refresh an expired GitHub access token by making a simple API call."""
    token_url = "https://github.com/login/oauth/access_token"
    data = {
        "client_id": settings.GITHUB_CLIENT_ID,
        "client_secret": settings.GITHUB_CLIENT_SECRET,
        "grant_type": "refresh_token",
        "refresh_token": user.refreshToken,
    }
    async with httpx.AsyncClient() as client:
        response = await client.post(
            token_url,
            headers={"Accept": "application/json"},
            data=data,
        )

        if response.status_code != 200:
            raise HTTPException(
                status_code=response.status_code, detail="Failed to authenticate with GitHub"
            )

        token_data = response.json()
        access_token = token_data.get("access_token")
        refresh_token = token_data.get("refresh_token")

        updated_user = await UserRepository.update_user(
            user=user,
            access_token=access_token,
            refresh_token=refresh_token,
            installation_ids=user.installationId,
            avatar_url=user.avatarUrl,
            name=user.name,
            email=user.email,
        )

        return updated_user
