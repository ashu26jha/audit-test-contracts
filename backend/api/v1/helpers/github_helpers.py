import re
from pathlib import PurePosixPath
from typing import List, Optional, Tuple
from urllib.parse import urljoin

import httpx
from fastapi import HTTPException
from tenacity import retry, retry_if_exception_type, stop_after_attempt, wait_exponential

from api.v1.models.user import User


class GithubHelpers:
    BASE_URL = "https://api.github.com"

    def __init__(self):
        self.client = httpx.AsyncClient(
            timeout=5.0, headers={"Accept": "application/vnd.github.v3+json"}, follow_redirects=True
        )

    async def __aenter__(self):
        return self

    async def __aexit__(self, exc_type, exc_value, traceback):
        await self.cleanup()

    async def cleanup(self):
        await self.client.aclose()

    def _create_github_headers(self, access_token: str) -> dict:
        return {
            "Authorization": f"token {access_token}",
            "Accept": "application/vnd.github.v3+json",
        }

    def _sanitize_endpoint(self, endpoint: str) -> str:
        """Sanitize the API endpoint path."""
        # Remove any leading/trailing slashes
        endpoint = endpoint.strip("/")
        # Use PurePosixPath to sanitize the path (removes .. and extra slashes)
        return str(PurePosixPath(endpoint))

    @retry(
        retry=retry_if_exception_type(HTTPException),
        stop=stop_after_attempt(3),
        wait=wait_exponential(multiplier=1, min=2, max=10),
    )
    async def github_get(
        self, endpoint: str, access_token: str, params: Optional[dict] = None
    ) -> dict:
        headers = self._create_github_headers(access_token)

        # Sanitize the endpoint and create the full URL
        sanitized_endpoint = self._sanitize_endpoint(endpoint)
        url = urljoin(f"{self.BASE_URL}/", sanitized_endpoint)

        response = await self.client.get(url, headers=headers, params=params)
        await self._handle_github_response(
            response, f"Failed to fetch data from {sanitized_endpoint}"
        )
        return response.json()

    def _parse_github_response(self, response: dict | list) -> List[dict]:
        """Parse GitHub API response and extract items."""
        if isinstance(response, dict):
            return response.get("repositories", [])
        elif isinstance(response, list):
            return response
        return []

    async def github_get_paginated(
        self,
        endpoint: str,
        access_token: str,
        params: Optional[dict] = None,
        force_pagination: bool = False,
    ) -> List[dict]:
        results = []
        params = params or {}
        params.update({"per_page": 100})

        response = await self.github_get(endpoint, access_token, params)
        items = self._parse_github_response(response)

        if len(items) < 100 or force_pagination is False:
            return items

        results.extend(items)

        # Continue with pagination
        for page in range(2, 11):
            params.update({"page": page})
            response = await self.github_get(endpoint, access_token, params)
            items = self._parse_github_response(response)

            results.extend(items)
            if len(items) < 100:
                break

        return results

    async def _handle_github_response(self, response: httpx.Response, error_message: str):
        if response.status_code == 401:
            raise HTTPException(
                status_code=401, detail="Unauthorized access. Access token required."
            )
        elif response.status_code == 404:
            raise HTTPException(status_code=404, detail=f"{error_message}: Resource not found.")
        elif response.status_code != 200:
            raise HTTPException(
                status_code=response.status_code,
                detail=f"{error_message}. Status {response.status_code}",
            )

    def parse_github_url(self, repo_url: str) -> Tuple[str, str]:
        pattern = (
            r"(?:https?://)?(?:www\.)?github\.com/(?P<owner>[^/]+)/(?P<repo>[^/]+)(?:\.git)?/?"
        )
        match = re.match(pattern, repo_url)
        if not match:
            raise HTTPException(status_code=400, detail="Invalid GitHub repository URL")
        return match.group("owner"), match.group("repo").replace(".git", "")

    async def get_installations(self, token: str) -> List[dict]:
        url = "user/installations"
        headers = {
            "Authorization": f"Bearer {token}",
            "X-GitHub-Api-Version": "2022-11-28",
        }

        response = await self.client.get(f"{self.BASE_URL}/{url}", headers=headers)
        await self._handle_github_response(response, "Failed to fetch installations")

        installations = response.json().get("installations", [])

        user = await User.find_one(User.accessToken == token)
        if user:
            new_installation_ids = [inst["id"] for inst in installations]
            if set(new_installation_ids) != set(user.installationId):
                await user.update({"$set": {"installationId": new_installation_ids}})

        return installations
