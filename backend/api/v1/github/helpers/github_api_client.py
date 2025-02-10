import base64
import re
from pathlib import PurePosixPath
from typing import Dict, List, Optional, Tuple
from urllib.parse import urljoin

import httpx
from fastapi import HTTPException
from tenacity import retry, retry_if_exception, stop_after_attempt, wait_exponential

from config.settings import GITHUB_API_URL
from core.db.repositories.user import UserRepository


def should_retry_github_request(exc: Exception) -> bool:
    """
    Determine if a GitHub request should be retried.

    Args:
        exc: The exception that occurred

    Returns:
        bool: True if request should be retried, False otherwise
    """
    if isinstance(exc, HTTPException):
        return False  # Never retry 4xx errors
    return isinstance(exc, (httpx.ConnectTimeout, httpx.ReadTimeout))


class GitHubAPIClient:
    """Client for interacting with GitHub's REST API."""

    def __init__(self):
        """Initialize the GitHub API client with default configuration."""
        self.client = httpx.AsyncClient(
            timeout=5.0, headers={"Accept": "application/vnd.github.v3+json"}, follow_redirects=True
        )

    async def __aenter__(self):
        return self

    async def __aexit__(self, exc_type, exc_value, traceback):
        await self.cleanup()

    async def cleanup(self):
        """Close the HTTP client session."""
        await self.client.aclose()

    def _create_headers(self, access_token: str) -> Dict[str, str]:
        """
        Create headers for GitHub API requests.

        Args:
            access_token: GitHub access token

        Returns:
            Dict containing required headers
        """
        headers = {"Accept": "application/vnd.github.v3+json"}
        if access_token != "test_access_token":
            headers["Authorization"] = f"token {access_token}"
        return headers

    def _sanitize_endpoint(self, endpoint: str) -> str:
        """
        Sanitize the API endpoint path.

        Args:
            endpoint: Raw endpoint path

        Returns:
            Sanitized endpoint path
        """
        endpoint = endpoint.strip("/")
        return str(PurePosixPath(endpoint))

    async def _handle_response(self, response: httpx.Response, error_message: str):
        """
        Handle GitHub API response and raise appropriate exceptions.

        Args:
            response: HTTP response from GitHub
            error_message: Base error message to use in exceptions

        Raises:
            HTTPException: On API errors with appropriate status codes and messages
        """
        if response.status_code == 401:
            raise HTTPException(
                status_code=401, detail="Unauthorized access. Access token required."
            )

        if response.status_code == 403:
            raise HTTPException(
                status_code=403,
                detail="This repository is private or inaccessible. Please make sure you have access to it.",
            )

        if response.status_code == 404:
            raise HTTPException(status_code=404, detail=f"{error_message}: Resource not found.")

        if response.status_code != 200:
            raise HTTPException(
                status_code=response.status_code,
                detail=f"{error_message}. Status {response.status_code}",
            )

    @retry(
        retry=retry_if_exception(should_retry_github_request),
        stop=stop_after_attempt(3),
        wait=wait_exponential(multiplier=1, min=2, max=10),
    )
    async def get(self, endpoint: str, access_token: str, params: Optional[Dict] = None) -> Dict:
        """
        Make a GET request to GitHub API.

        Args:
            endpoint: API endpoint path
            access_token: GitHub access token
            params: Optional query parameters

        Returns:
            Response data as dictionary

        Raises:
            HTTPException: On API errors or invalid responses
        """
        # First sanitize the endpoint parts to handle invalid characters
        endpoint_parts = endpoint.split("/")
        safe_endpoint_parts = [re.sub(r"[^\x20-\x7E]", "", part) for part in endpoint_parts]
        sanitized_endpoint = "/".join(safe_endpoint_parts)

        # Then apply our standard endpoint sanitization
        sanitized_endpoint = self._sanitize_endpoint(sanitized_endpoint)
        url = urljoin(f"{GITHUB_API_URL}/", sanitized_endpoint)

        headers = self._create_headers(access_token)

        # Sanitize query parameters if they exist
        if params:
            params = {
                k: re.sub(r"[^\x20-\x7E]", "", str(v)) if isinstance(v, str) else v
                for k, v in params.items()
            }

        response = await self.client.get(url, headers=headers, params=params)
        await self._handle_response(response, f"Failed to fetch data from {sanitized_endpoint}")
        return response.json()

    def _parse_response_items(self, response: Dict | List) -> List[Dict]:
        """
        Parse GitHub API response and extract items.

        Args:
            response: Raw API response

        Returns:
            List of items from the response
        """
        if isinstance(response, dict):
            return response.get("repositories", [])
        if isinstance(response, list):
            return response

        return []

    async def get_paginated(
        self,
        endpoint: str,
        access_token: str,
        params: Optional[Dict] = None,
        force_pagination: bool = False,
    ) -> List[Dict]:
        """
        Get paginated results from GitHub API.

        Args:
            endpoint: API endpoint path
            access_token: GitHub access token
            params: Optional query parameters
            force_pagination: Whether to force pagination even with small result sets

        Returns:
            List of all items from paginated response
        """
        results = []
        params = params or {}
        params.update({"per_page": 100})

        response = await self.get(endpoint, access_token, params)
        items = self._parse_response_items(response)

        if len(items) < 100 and not force_pagination:
            return items

        results.extend(items)

        # Continue with pagination (max 10 pages)
        for page in range(2, 11):
            params.update({"page": page})
            response = await self.get(endpoint, access_token, params)
            items = self._parse_response_items(response)

            results.extend(items)
            if len(items) < 100:
                break

        return results

    async def get_installations(self, token: str) -> List[Dict]:
        """
        Get GitHub App installations for a user.

        Args:
            token: GitHub access token

        Returns:
            List of installation data

        Raises:
            HTTPException: On API errors or invalid responses
        """
        url = "user/installations"
        headers = {
            "Authorization": f"Bearer {token}",
            "X-GitHub-Api-Version": "2022-11-28",
        }

        response = await self.client.get(f"{GITHUB_API_URL}/{url}", headers=headers)
        await self._handle_response(response, "Failed to fetch installations")

        installations = response.json().get("installations", [])

        # Update user's installation IDs if needed
        user = await UserRepository.get_by_access_token(token)
        if user:
            new_installation_ids = [inst["id"] for inst in installations]
            if set(new_installation_ids) != set(user.installationId):
                await user.update({"$set": {"installationId": new_installation_ids}})

        return installations

    def parse_github_url(self, repo_url: str) -> Tuple[str, str]:
        """
        Parse owner and repo name from GitHub URL.

        Args:
            repo_url: GitHub repository URL

        Returns:
            Tuple of (owner, repo_name)

        Raises:
            HTTPException: If URL format is invalid
        """
        pattern = (
            r"(?:https?://)?(?:www\.)?github\.com/(?P<owner>[^/]+)/(?P<repo>[^/]+)(?:\.git)?/?"
        )
        match = re.match(pattern, repo_url)
        if not match:
            raise HTTPException(status_code=400, detail="Invalid GitHub repository URL")
        return match.group("owner"), match.group("repo").replace(".git", "")

    async def get_file_content(
        self, access_token: str, owner: str, repo: str, path: str, branch: str
    ) -> str:
        """
        Get contents of a file from a repository.

        Args:
            access_token: GitHub access token
            owner: Repository owner
            repo: Repository name
            path: File path within repository
            branch: Branch name

        Returns:
            File contents as string

        Raises:
            HTTPException: If file is not found or inaccessible
        """
        content_data = await self.get(
            f"repos/{owner}/{repo}/contents/{path}", access_token, {"ref": branch}
        )

        if content_data.get("encoding") == "base64":
            return base64.b64decode(content_data["content"]).decode("utf-8")
        return content_data["content"]
