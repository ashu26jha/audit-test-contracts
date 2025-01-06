import httpx
from fastapi import HTTPException

from config.settings import GITHUB_API_URL


async def validate_github_token(access_token: str) -> bool:
    """Validate a GitHub access token by making a simple API call."""
    async with httpx.AsyncClient() as client:
        response = await client.get(
            f"{GITHUB_API_URL}/user",
            headers={
                "Authorization": f"token {access_token}",
                "Accept": "application/vnd.github.v3+json",
            },
        )

        if response.status_code == 401:
            raise HTTPException(status_code=401, detail="Invalid GitHub token")

        if response.status_code != 200:
            raise HTTPException(status_code=response.status_code, detail="GitHub API error")

        return True
