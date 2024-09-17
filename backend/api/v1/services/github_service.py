import httpx
from fastapi import HTTPException
import config.settings as settings


class GitHubService:
    BASE_URL = "https://api.github.com"

    async def get_user_data(self, access_token: str) -> dict:
        """
        Fetch user data from GitHub API using the provided access token.
        """
        headers = {
            "Authorization": f"token {access_token}",
            "Accept": "application/vnd.github.v3+json"
        }

        async with httpx.AsyncClient() as client:
            response = await client.get(f"{self.BASE_URL}/user", headers=headers)

        if response.status_code != 200:
            raise HTTPException(
                status_code=400, detail="Failed to fetch user data from GitHub")

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
            "Accept": "application/vnd.github.v3+json"
        }

        async with httpx.AsyncClient() as client:
            response = await client.get(f"{self.BASE_URL}/user/emails", headers=headers)

        if response.status_code != 200:
            raise HTTPException(
                status_code=400, detail="Failed to fetch user emails from GitHub")

        emails = response.json()
        primary_email = next((email["email"]
                             for email in emails if email["primary"]), None)

        if not primary_email:
            raise HTTPException(
                status_code=400, detail="No primary email found for the user")

        return primary_email

    async def get_user_repositories(self, access_token: str) -> list:
        """
        Fetch user's repositories from GitHub API.
        """
        headers = {
            "Authorization": f"token {access_token}",
            "Accept": "application/vnd.github.v3+json"
        }

        async with httpx.AsyncClient() as client:
            response = await client.get(f"{self.BASE_URL}/user/repos", headers=headers)

        if response.status_code != 200:
            raise HTTPException(
                status_code=400, detail="Failed to fetch user repositories from GitHub")

        return response.json()

    async def get_repository_contents(self, access_token: str, owner: str, repo: str, path: str = "") -> list:
        """
        Fetch contents of a repository or a specific path within a repository.
        """
        headers = {
            "Authorization": f"token {access_token}",
            "Accept": "application/vnd.github.v3+json"
        }

        url = f"{self.BASE_URL}/repos/{owner}/{repo}/contents/{path}"

        async with httpx.AsyncClient() as client:
            response = await client.get(url, headers=headers)

        if response.status_code != 200:
            raise HTTPException(
                status_code=400, detail="Failed to fetch repository contents from GitHub")

        return response.json()

    async def get_file_content(self, access_token: str, owner: str, repo: str, path: str) -> str:
        """
        Fetch the content of a specific file in a repository.
        """
        headers = {
            "Authorization": f"token {access_token}",
            "Accept": "application/vnd.github.v3+json"
        }

        url = f"{self.BASE_URL}/repos/{owner}/{repo}/contents/{path}"

        async with httpx.AsyncClient() as client:
            response = await client.get(url, headers=headers)

        if response.status_code != 200:
            raise HTTPException(
                status_code=400, detail="Failed to fetch file content from GitHub")

        content_data = response.json()
        if content_data.get("encoding") == "base64":
            import base64
            return base64.b64decode(content_data["content"]).decode("utf-8")
        else:
            return content_data["content"]

    async def get_user_organizations(self, access_token: str) -> list:
        async with httpx.AsyncClient() as client:
            response = await client.get(
                f"{self.BASE_URL}/user/orgs",
                headers={"Authorization": f"token {access_token}"}
            )
        response.raise_for_status()
        return [org["login"] for org in response.json()]

    async def get_organization_repositories(self, access_token: str, org: str) -> list:
        async with httpx.AsyncClient() as client:
            response = await client.get(
                f"{self.BASE_URL}/orgs/{org}/repos",
                headers={"Authorization": f"token {access_token}"}
            )
        response.raise_for_status()
        return [{"name": repo["name"], "updatedAt": repo["updated_at"]} for repo in response.json()]

    async def get_user_organizations_and_personal(self, access_token: str) -> list:
        async with httpx.AsyncClient() as client:
            orgs_response = await client.get(
                f"{self.BASE_URL}/user/orgs",
                headers={"Authorization": f"token {access_token}"}
            )
            user_response = await client.get(
                f"{self.BASE_URL}/user",
                headers={"Authorization": f"token {access_token}"}
            )

        orgs = [{"login": org["login"], "type": "organization"}
                for org in orgs_response.json()] if orgs_response.status_code == 200 else []
        user = {"login": user_response.json(
        )["login"], "type": "user"} if user_response.status_code == 200 else None

        return [user] + orgs if user else orgs

    async def get_repositories(self, access_token: str, owner: str, owner_type: str) -> list:
        url = f"{self.BASE_URL}/users/{owner}/repos" if owner_type == "user" else f"{self.BASE_URL}/orgs/{owner}/repos"
        async with httpx.AsyncClient() as client:
            response = await client.get(
                url,
                headers={"Authorization": f"token {access_token}"}
            )
        response.raise_for_status()
        return [{"name": repo["name"], "updatedAt": repo["updated_at"]} for repo in response.json()]

    # async def get_repository_contents(self, access_token: str, owner: str, repo: str, path: str = "") -> list:
    #     url = f"{self.BASE_URL}/repos/{owner}/{repo}/contents/{path}"
    #     async with httpx.AsyncClient() as client:
    #         response = await client.get(
    #             url,
    #             headers={"Authorization": f"token {access_token}"}
    #         )
    #     response.raise_for_status()
    #     contents = response.json()
    #     if isinstance(contents, list):
    #         return [
    #             {
    #                 "name": item["name"],
    #                 "path": item["path"],
    #                 "type": item["type"],
    #                 "download_url": item.get("download_url")
    #             }
    #             for item in contents
    #             if item["type"] == "file" and item["name"].endswith(".sol")
    #         ]
    #     return []

    async def get_repository_contents(self, access_token: str, owner: str, repo: str, path: str = "") -> list:
        async def fetch_contents(path):
            url = f"{self.BASE_URL}/repos/{owner}/{repo}/contents/{path}"
            async with httpx.AsyncClient() as client:
                response = await client.get(
                    url,
                    headers={"Authorization": f"token {access_token}"}
                )
            response.raise_for_status()
            return response.json()

        async def recursive_fetch(path=""):
            contents = await fetch_contents(path)
            result = []
            for item in contents:
                if item["type"] == "file" and item["name"].endswith(".sol"):
                    result.append({
                        "name": item["name"],
                        "path": item["path"],
                        "type": "file",
                        "download_url": item["download_url"]
                    })
                elif item["type"] == "dir":
                    result.extend(await recursive_fetch(item["path"]))
            return result

        return await recursive_fetch()
