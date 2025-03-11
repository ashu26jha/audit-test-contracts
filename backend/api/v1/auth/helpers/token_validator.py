from typing import Tuple

from fastapi import HTTPException

from config import settings
from config.settings import GITHUB_API_URL
from core.db.repositories.user import UserRepository
from core.models.user import User
from core.utils.errors import TokenError
from core.utils.http_client import get_http_client


async def get_github_access_token(data: dict) -> Tuple[str, str]:
    """Get a GitHub access token from either the user's GH code or refresh token."""

    token_url = "https://github.com/login/oauth/access_token"

    async with get_http_client() as client:
        response = await client.post(
            token_url,
            data=data,
        )

        if response.status_code != 200:
            raise TokenError(message="Failed to authenticate with GitHub")

        token_data = response.json()

        if token_data.get("error"):
            raise TokenError(
                message="Invalid refresh token",
                details={"error": token_data.get("error_description")},
            )

        access_token = token_data.get("access_token")
        refresh_token = token_data.get("refresh_token")

        if not access_token:
            raise TokenError(message="Invalid token response")

        return access_token, refresh_token


async def validate_github_token(user: User) -> User:
    """Validate a GitHub access token by making a simple API call."""
    async with get_http_client() as client:
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
    """Refresh an expired GitHub access token"""
    data = {
        "client_id": settings.GITHUB_CLIENT_ID,
        "client_secret": settings.GITHUB_CLIENT_SECRET,
        "grant_type": "refresh_token",
        "refresh_token": user.refreshToken,
    }

    access_token, refresh_token = await get_github_access_token(data)

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
