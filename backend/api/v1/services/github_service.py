import asyncio
import base64
import re
from uuid import uuid4

import httpx
from fastapi import HTTPException

from api.v1.models.github import GitHubRepo
from api.v1.models.user import User
from api.v1.schemas.github_schema import GitHubRepoCreate, GitHubRepoResponse
from common import logger
from config import settings


class GitHubService:
    BASE_URL = "https://api.github.com"

    async def get_user_data(self, access_token: str) -> dict:
        """
        Fetch user data from GitHub API using the provided access token.
        """
        headers = {
            "Authorization": f"token {access_token}",
            "Accept": "application/vnd.github.v3+json",
        }

        async with httpx.AsyncClient() as client:
            response = await client.get(f"{self.BASE_URL}/user", headers=headers)

        if response.status_code != 200:
            raise HTTPException(status_code=400, detail="Failed to fetch user data from GitHub")

        user_data = response.json()

        # If email is not public, fetch it separately
        if not user_data.get("email"):
            email = await self.get_primary_email(access_token)
            user_data["email"] = email

        return user_data

    async def get_primary_email(self, access_token: str) -> str:
        """
        Fetch the user's primary email address from GitHub API.
        """
        headers = {
            "Authorization": f"token {access_token}",
            "Accept": "application/vnd.github.v3+json",
        }

        async with httpx.AsyncClient() as client:
            response = await client.get(f"{self.BASE_URL}/user/emails", headers=headers)

        if response.status_code != 200:
            raise HTTPException(status_code=400, detail="Failed to fetch user emails from GitHub")

        emails = response.json()
        primary_email = next((email["email"] for email in emails if email["primary"]), None)

        if not primary_email:
            raise HTTPException(status_code=400, detail="No primary email found for the user")

        return primary_email

    async def get_repository_contents(
        self, access_token: str, owner: str, repo: str, branch: str, path: str = ""
    ) -> list:
        url = f"{self.BASE_URL}/repos/{owner}/{repo}/git/trees/{branch}"
        params = {"recursive": 1}
        headers = {"Authorization": f"token {access_token}"}

        async with httpx.AsyncClient() as client:
            response = await client.get(url, headers=headers, params=params)
        response.raise_for_status()

        tree = response.json()["tree"]
        files = [
            {
                "name": item["path"].split("/")[-1],
                "path": item["path"],
                "type": "file",
                "download_url": f"https://raw.githubusercontent.com/{owner}/{repo}/{branch}/{item['path']}",
            }
            for item in tree
            if item["type"] == "blob" and item["path"].endswith(".sol")
        ]

        tasks = [
            self.get_file_content(access_token, owner, repo, file["path"], branch) for file in files
        ]
        file_contents = await asyncio.gather(*tasks, return_exceptions=True)

        for file, file_content in zip(files, file_contents):
            file["token"] = int(len(file_content) / 4)
            file["lineCount"] = len(file_content.split("\n"))

        return files

    async def get_file_content(
        self, access_token: str, owner: str, repo: str, path: str, branch: str
    ) -> str:
        """
        Fetch the content of a specific file in a repository.
        """
        params = {"ref": branch}
        headers = {
            "Authorization": f"token {access_token}",
            "Accept": "application/vnd.github.v3+json",
        }

        url = f"{self.BASE_URL}/repos/{owner}/{repo}/contents/{path}"
        params = {"ref": branch}

        async with httpx.AsyncClient() as client:
            response = await client.get(url, headers=headers, params=params)

        if response.status_code != 200:
            raise HTTPException(
                status_code=response.status_code,
                detail=f"Failed to fetch file content from GitHub: {response.text}",
            )

        content_data = response.json()
        if content_data.get("encoding") == "base64":
            return base64.b64decode(content_data["content"]).decode("utf-8")

        return content_data["content"]

    async def get_installations(self, token: str) -> list:
        url = "https://api.github.com/user/installations"
        headers = {
            "Authorization": f"Bearer {token}",
            "X-GitHub-Api-Version": "2022-11-28",
        }

        async with httpx.AsyncClient() as client:
            response = await client.get(url, headers=headers)

        installations = response.json().get("installations", [])

        # Update user's installation IDs atomically
        user = await User.find_one(User.accessToken == token)
        if user:
            new_installation_ids = [inst["id"] for inst in installations]
            # Only update if there are actual changes
            if set(new_installation_ids) != set(user.installationId):
                await user.update({"$set": {"installationId": new_installation_ids}})
                logger.info(f"Updated installation IDs for user {user.id}")

        return installations

    async def get_accessible_repositories(self, access_token: str) -> list:
        """
        Returns the repositories for which the GitHub App has access to
        """
        installations = await self.get_installations(access_token)
        installation_repos = []
        for installation in installations:
            installation_id = installation["id"]
            url = f"https://api.github.com/user/installations/{installation_id}/repositories"
            headers = {
                "Authorization": f"Bearer {access_token}",
                "X-GitHub-Api-Version": "2022-11-28",
                "Accept": "application/vnd.github+json",
            }

            async with httpx.AsyncClient() as client:
                response = await client.get(url, headers=headers)

            if response.status_code != 200:
                logger.error(
                    f"Failed to fetch repositories. Status: {response.status_code}, Response: {response.text}"
                )
                raise HTTPException(
                    status_code=response.status_code, detail=f"GitHub API error: {response.text}"
                )

            data = response.json()
            repositories = [
                {
                    "name": repo["name"],
                    "updatedAt": repo["updated_at"],
                    "private": repo["private"],
                    "owner": repo["owner"]["login"],
                }
                for repo in data.get("repositories", [])
            ]
            installation_repos.extend(repositories)

        return installation_repos

    async def get_repository_branches(self, access_token: str, owner: str, repo: str) -> list:

        repo_url = f"{self.BASE_URL}/repos/{owner}/{repo}"
        headers = {
            "Authorization": f"token {access_token}",
            "Accept": "application/vnd.github+json",
        }

        async with httpx.AsyncClient() as client:
            repo_response = await client.get(repo_url, headers=headers)
            repo_response.raise_for_status()
            repo_data = repo_response.json()
            default_branch = repo_data.get("default_branch")

            branches_url = f"{self.BASE_URL}/repos/{owner}/{repo}/branches"
            branches_response = await client.get(branches_url, headers=headers)
            branches_response.raise_for_status()

            return [
                {"name": branch["name"], "isDefault": branch["name"] == default_branch}
                for branch in branches_response.json()
            ]

    async def get_commit_hash(
        self, access_token: str, repository_url: str, branch_name: str
    ) -> str:
        """
        Fetch the latest commit hash from the specified branch of the repository.
        """
        headers = {
            "Accept": "application/vnd.github.v3+json",
        }

        # Include access token if provided
        if access_token:
            headers["Authorization"] = f"token {access_token}"

        # Improved URL parsing
        pattern = (
            r"(?:https?://)?(?:www\.)?github\.com/(?P<owner>[^/]+)/(?P<repo>[^/]+)(?:\.git)?/?"
        )
        match = re.match(pattern, repository_url)
        if not match:
            message = "Invalid GitHub repository URL."
            logger.error(message)
            raise HTTPException(status_code=400, detail=message)

        owner = match.group("owner")
        repo = match.group("repo").replace(".git", "")

        url = f"{self.BASE_URL}/repos/{owner}/{repo}/commits/{branch_name}"

        try:
            async with httpx.AsyncClient() as client:
                response = await client.get(url, headers=headers)

                if (
                    settings.ENVIRONMENT == "development"
                    and response.status_code == 401
                    and access_token
                ):
                    logger.warning("Invalid access token provided. Retrying without access token.")
                    headers.pop("Authorization", None)
                    response = await client.get(url, headers=headers)

                if response.status_code == 200:
                    commit_data = response.json()
                elif response.status_code == 401:
                    message = "Unauthorized access. Access token required for private repositories."
                    logger.error(message)
                    raise HTTPException(status_code=401, detail=message)
                elif response.status_code == 404:
                    message = f"Repository or branch '{branch_name}' not found."
                    logger.error(message)
                    raise HTTPException(status_code=404, detail=message)
                else:
                    api_message = response.json().get("message", "No message provided")
                    message = (
                        f"Failed to fetch commit hash for branch '{branch_name}'. "
                        f"GitHub API returned status {response.status_code}: {api_message}"
                    )
                    logger.error(message)
                    raise HTTPException(status_code=500, detail="Internal Error Server")

            commit_hash = commit_data.get("sha")
            if not commit_hash:
                message = f"Commit hash not found for branch '{branch_name}'."
                logger.error(message)
                raise HTTPException(status_code=500, detail="Internal Error Server")

            return commit_hash

        except HTTPException as e:
            raise e
        except Exception as e:
            message = f"Unexpected error while fetching commit hash: {str(e)}"
            logger.error(message)
            raise HTTPException(status_code=500, detail="Internal Error Server")

    async def fetch_github_repo_info(self, access_token: str, repo_url: str) -> GitHubRepoCreate:
        headers = {
            "Authorization": f"token {access_token}",
            "Accept": "application/vnd.github.v3+json",
        }

        # Improved URL parsing
        pattern = (
            r"(?:https?://)?(?:www\.)?github\.com/(?P<owner>[^/]+)/(?P<repo>[^/]+)(?:\.git)?/?"
        )
        match = re.match(pattern, repo_url)
        if not match:
            raise HTTPException(status_code=400, detail="Invalid GitHub repository URL")

        owner = match.group("owner")
        repo = match.group("repo").replace(".git", "")

        url = f"{self.BASE_URL}/repos/{owner}/{repo}"

        async with httpx.AsyncClient() as client:
            response = await client.get(url, headers=headers)

            if (
                settings.ENVIRONMENT == "development"
                and response.status_code == 401
                and access_token
            ):
                logger.warning("Invalid access token provided. Retrying without access token.")
                headers.pop("Authorization", None)
                response = await client.get(url, headers=headers)

            if response.status_code != 200:
                raise HTTPException(status_code=response.status_code, detail=response.text)

        data = response.json()

        return GitHubRepoCreate(
            repo_url=repo_url,
            repo_name=data.get("name", ""),
            repo_full_name=data.get("full_name", ""),
        )

    async def save_github_repo_info(self, repo_info: GitHubRepoCreate) -> GitHubRepo:
        db_repo = GitHubRepo(
            id=uuid4(),
            repo_url=repo_info.repo_url,
            repo_name=repo_info.repo_name,
            repo_full_name=repo_info.repo_full_name,
        )
        await db_repo.insert()
        return db_repo

    async def get_github_repo_info(self, access_token: str, repo_url: str) -> GitHubRepoResponse:
        repo_info = await self.fetch_github_repo_info(access_token, repo_url)
        saved_repo = await self.save_github_repo_info(repo_info)
        return GitHubRepoResponse(
            id=saved_repo.id,
            repo_url=saved_repo.repo_url,
            repo_name=saved_repo.repo_name,
            repo_full_name=saved_repo.repo_full_name,
        )

    async def check_repository_access(self, access_token: str, repo_url: str) -> dict:
        """
        Check if the authenticated user has access to the repository
        and return repository information.
        """
        pattern = (
            r"(?:https?://)?(?:www\.)?github\.com/(?P<owner>[^/]+)/(?P<repo>[^/]+)(?:\.git)?/?"
        )
        match = re.match(pattern, repo_url)
        if not match:
            raise HTTPException(status_code=400, detail="Invalid GitHub repository URL")

        owner = match.group("owner")
        repo = match.group("repo").replace(".git", "")

        url = f"{self.BASE_URL}/repos/{owner}/{repo}"

        headers = {
            "Authorization": f"token {access_token}",
            "Accept": "application/vnd.github.v3+json",
        }

        async with httpx.AsyncClient() as client:
            response = await client.get(url, headers=headers)

        if response.status_code == 200:
            data = response.json()
            return data
        elif response.status_code == 404:
            raise HTTPException(status_code=404, detail="Repository not found or access denied")
        else:
            raise HTTPException(
                status_code=response.status_code, detail="Error accessing repository"
            )
