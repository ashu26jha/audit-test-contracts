import asyncio
import base64
from typing import Dict, List

from fastapi import HTTPException

from api.v1.helpers.github_helpers import GithubHelpers
from api.v1.helpers.lines_of_code_helpers import analyze_file_content
from api.v1.schemas.github_schema import GitHubRepoResponse
from common.token_count import count_tokens


class GitHubService:
    def __init__(self):
        self.github_helpers = GithubHelpers()

    async def get_user_data(self, access_token: str) -> dict:
        user_data = await self.github_helpers.github_get("user", access_token)

        if not user_data.get("email"):
            user_data["email"] = await self.get_primary_email(access_token)

        return user_data

    async def get_primary_email(self, access_token: str) -> str:
        emails = await self.github_helpers.github_get("user/emails", access_token)
        primary_email = next((email["email"] for email in emails if email["primary"]), None)

        if not primary_email:
            raise HTTPException(status_code=400, detail="No primary email found")

        return primary_email

    async def get_repository_contents(
        self, access_token: str, owner: str, repo: str, branch: str, path: str = ""
    ) -> List[Dict[str, str]]:
        url = f"repos/{owner}/{repo}/git/trees/{branch}"
        response = await self.github_helpers.github_get(url, access_token, {"recursive": 1})

        # Filter for .sol files
        sol_files = [
            item
            for item in response["tree"]
            if item["type"] == "blob" and item["path"].endswith(".sol")
        ]

        # Fetch contents in parallel
        async def get_file_info(file_item):
            content = await self.get_file_content(
                access_token, owner, repo, file_item["path"], branch
            )
            line_count = await analyze_file_content(content, file_item["path"])
            return {
                "name": file_item["path"].split("/")[-1],
                "path": file_item["path"],
                "type": "file",
                "download_url": f"https://raw.githubusercontent.com/{owner}/{repo}/{branch}/{file_item['path']}",
                "token": count_tokens(content),
                "lineCount": line_count["total_lines"],
            }

        # Use asyncio.gather for parallel requests
        tasks = [get_file_info(file) for file in sol_files]
        files = await asyncio.gather(*tasks)

        return files

    async def get_file_content(
        self, access_token: str, owner: str, repo: str, path: str, branch: str
    ) -> str:
        url = f"repos/{owner}/{repo}/contents/{path}"
        content_data = await self.github_helpers.github_get(url, access_token, {"ref": branch})

        if content_data.get("encoding") == "base64":
            return base64.b64decode(content_data["content"]).decode("utf-8")

        return content_data["content"]

    async def get_accessible_repositories(self, access_token: str) -> List[Dict[str, str]]:
        installations = await self.github_helpers.get_installations(access_token)
        all_repos = []

        for installation in installations:
            repository_selection = installation.get("repository_selection", "selected")

            # Get selected repositories
            repos = await self.github_helpers.github_get_paginated(
                f"user/installations/{installation['id']}/repositories",
                access_token,
                force_pagination=True,
            )

            formatted_repos = [
                {
                    "name": repo["name"],
                    "updatedAt": repo["updated_at"],
                    "private": repo["private"],
                    "owner": repo["owner"]["login"],
                    "all_repos_access": repository_selection == "all",
                }
                for repo in repos
            ]
            all_repos.extend(formatted_repos)

        return all_repos

    async def get_repository_branches(self, access_token: str, owner: str, repo: str) -> List:
        repo_data = await self.github_helpers.github_get(f"repos/{owner}/{repo}", access_token)
        default_branch = repo_data.get("default_branch")

        branches = await self.github_helpers.github_get_paginated(
            f"repos/{owner}/{repo}/branches", access_token, force_pagination=True
        )

        return [
            {"name": branch["name"], "isDefault": branch["name"] == default_branch}
            for branch in branches
        ]

    async def get_github_repo_info(self, access_token: str, repo_url: str) -> GitHubRepoResponse:
        """Get repository information"""
        owner, repo = self.github_helpers.parse_github_url(repo_url)
        repo_data = await self.github_helpers.github_get(f"repos/{owner}/{repo}", access_token)

        return GitHubRepoResponse(
            repo_name=repo_data["name"],
            repo_full_name=repo_data["full_name"],
            owner=repo_data["owner"]["login"],
            default_branch=repo_data.get("default_branch", "main"),
            repo_url=repo_url,
        )

    async def get_commit_hash(
        self, access_token: str, repository_url: str, branch_name: str
    ) -> str:
        """Fetch the latest commit hash from the specified branch of the repository."""
        owner, repo = self.github_helpers.parse_github_url(repository_url)
        url = f"repos/{owner}/{repo}/commits/{branch_name}"

        commit_data = await self.github_helpers.github_get(url, access_token)
        commit_hash = commit_data.get("sha")

        if not commit_hash:
            raise HTTPException(status_code=500, detail="Failed to fetch commit hash")

        return commit_hash
