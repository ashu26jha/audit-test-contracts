import asyncio
from typing import List

from api.v1.common.lines_of_code import analyze_file_content
from api.v1.github.helpers.github_api_client import GitHubAPIClient
from api.v1.github.schema import (
    FileType,
    GitHubBranch,
    GitHubFileContent,
    GitHubRepoInfo,
    GitHubRepository,
)
from core.utils.errors import HTTPClientError, RepositoryError, ValidationError
from core.utils.token_count import count_tokens


class GitHubService:
    """GitHub service class"""

    def __init__(self):
        self.client = GitHubAPIClient()

    async def get_user_data(self, access_token: str) -> dict:
        """
        Get user data from GitHub API.

        Args:
            access_token: GitHub access token

        Returns:
            User data including email

        Raises:
            AuthError: On authentication or permission issues
            RepositoryError: On resource not found
            HTTPClientError: On other HTTP errors
        """
        user_data = await self.client.get("user", access_token)

        if not user_data.get("email"):
            user_data["email"] = await self.get_primary_email(access_token)

        return user_data

    async def get_primary_email(self, access_token: str) -> str:
        """
        Get user's primary email from GitHub API.

        Args:
            access_token: GitHub access token

        Returns:
            Primary email address

        Raises:
            ValidationError: If no primary email is found
            AuthError: On authentication or permission issues
            RepositoryError: On resource not found
            HTTPClientError: On other HTTP errors
        """
        emails = await self.client.get("user/emails", access_token)
        primary_email = next((email["email"] for email in emails if email["primary"]), None)

        if not primary_email:
            raise ValidationError("No primary email found", {"access_token_valid": True})

        return primary_email

    async def get_repository_contents(
        self,
        access_token: str,
        owner: str,
        repo: str,
        branch: str,
        path: str = "",
        file_type: str = FileType.SOLIDITY,
    ) -> List[GitHubFileContent]:
        """
        Get repository contents filtered by file type.

        Args:
            access_token: GitHub access token
            owner: Repository owner
            repo: Repository name
            branch: Branch name
            path: Optional path within repository
            file_type: Type of files to fetch (sol or readme)

        Returns:
            List of GitHubFileContent information including content analysis

        Raises:
            ValidationError: If file type is invalid
            RepositoryError: If no matching files found or branch doesn't exist
            AuthError: On authentication or permission issues
            HTTPClientError: On other HTTP errors
        """
        if not isinstance(file_type, FileType):
            if file_type not in [t.value for t in FileType]:
                raise ValidationError(
                    f"Invalid file type. Must be one of: {', '.join([t.value for t in FileType])}",
                    {"provided_file_type": file_type, "valid_types": [t.value for t in FileType]},
                )
            file_type = FileType(file_type)

        url = f"repos/{owner}/{repo}/git/trees/{branch}"
        response = await self.client.get(url, access_token, {"recursive": 1})

        # Filter files based on type
        if file_type == FileType.README:
            files = [
                item
                for item in response["tree"]
                if item["type"] == "blob" and item["path"].lower().endswith(".md")
            ]
        else:  # Default to .sol files
            files = [
                item
                for item in response["tree"]
                if item["type"] == "blob" and item["path"].endswith(".sol")
            ]

        if not files:
            file_desc = "README" if file_type == FileType.README else "Solidity"
            raise RepositoryError(
                f"No {file_desc} files found in the repository",
                {"owner": owner, "repo": repo, "branch": branch, "file_type": str(file_type)},
            )

        # Fetch contents in parallel
        async def get_file_info(file_item):
            content = await self.client.get_file_content(
                access_token, owner, repo, file_item["path"], branch
            )
            is_readme = file_type == FileType.README
            analysis = await analyze_file_content(content, file_item["path"], is_readme)

            result = GitHubFileContent(
                name=file_item["path"].split("/")[-1],
                path=file_item["path"],
                type="file",
                download_url=f"https://raw.githubusercontent.com/{owner}/{repo}/{branch}/{file_item['path']}",
                token=count_tokens(content),
                lineCount=analysis.total_lines if not is_readme else None,
                character_count=analysis.character_count if is_readme else None,
                non_whitespace_character_count=(
                    analysis.non_whitespace_character_count if is_readme else None
                ),
            )
            return result

        tasks = [get_file_info(file) for file in files]
        return await asyncio.gather(*tasks)

    async def get_accessible_repositories(self, access_token: str) -> List[GitHubRepository]:
        """
        Get list of repositories accessible to the user.

        Args:
            access_token: GitHub access token

        Returns:
            List of repository information

        Raises:
            AuthError: On authentication or permission issues
            RepositoryError: On resource not found
            HTTPClientError: On other HTTP errors
        """
        installations = await self.client.get_installations(access_token)
        all_repos: list[GitHubRepository] = []

        for installation in installations:
            repository_selection = installation.get("repository_selection", "selected")

            repos = await self.client.get_paginated(
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

    async def get_repository_branches(
        self, access_token: str, owner: str, repo: str
    ) -> List[GitHubBranch]:
        """
        Get list of repository branches.

        Args:
            access_token: GitHub access token
            owner: Repository owner
            repo: Repository name

        Returns:
            List of branch information

        Raises:
            AuthError: On authentication or permission issues
            RepositoryError: On resource not found
            HTTPClientError: On other HTTP errors
        """
        repo_data = await self.client.get(f"repos/{owner}/{repo}", access_token)
        default_branch = repo_data.get("default_branch")

        branches = await self.client.get_paginated(
            f"repos/{owner}/{repo}/branches", access_token, force_pagination=True
        )

        return [
            {"name": branch["name"], "isDefault": branch["name"] == default_branch}
            for branch in branches
        ]

    async def get_github_repo_info(self, access_token: str, repo_url: str) -> GitHubRepoInfo:
        """
        Get repository information.

        Args:
            access_token: GitHub access token
            repo_url: Repository URL

        Returns:
            GitHubRepoInfo object

        Raises:
            AuthError: On authentication or permission issues
            RepositoryError: On resource not found or invalid URL
            HTTPClientError: On other HTTP errors
        """
        owner, repo = self.client.parse_github_url(repo_url)
        repo_data = await self.client.get(f"repos/{owner}/{repo}", access_token)

        return GitHubRepoInfo(
            repo_name=repo_data["name"],
            repo_full_name=repo_data["full_name"],
            owner=repo_data["owner"]["login"],
            default_branch=repo_data.get("default_branch", "main"),
            repo_url=repo_url,
        )

    async def get_commit_hash(
        self, access_token: str, repository_url: str, branch_name: str
    ) -> str:
        """
        Fetch the latest commit hash from the specified branch.

        Args:
            access_token: GitHub access token
            repository_url: Repository URL
            branch_name: Branch name

        Returns:
            Commit hash

        Raises:
            HTTPClientError: If commit hash cannot be fetched
            AuthError: On authentication or permission issues
            RepositoryError: On resource not found or invalid URL
        """
        owner, repo = self.client.parse_github_url(repository_url)
        url = f"repos/{owner}/{repo}/commits/{branch_name}"

        commit_data = await self.client.get(url, access_token)
        commit_hash = commit_data.get("sha")

        if not commit_hash:
            raise HTTPClientError(
                "Failed to fetch commit hash", {"owner": owner, "repo": repo, "branch": branch_name}
            )

        return commit_hash

    async def validate_repository_access(self, access_token: str, repo_url: str) -> bool:
        """
        Validates if a repository is accessible.

        Args:
            access_token: GitHub access token
            repo_url: Repository URL

        Returns:
            True if repository is accessible

        Raises:
            AuthError: When authentication to the repository fails
            RepositoryError: When repository is not found or URL is invalid
            HTTPClientError: On other HTTP errors
        """
        await self.get_github_repo_info(access_token, repo_url)
        return True
