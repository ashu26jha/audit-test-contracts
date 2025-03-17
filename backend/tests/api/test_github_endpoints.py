# pylint: disable=redefined-outer-name
from unittest.mock import AsyncMock, patch

import pytest
from fastapi import HTTPException
from fastapi.testclient import TestClient

from main import app


@pytest.fixture(scope="module")
def client():
    return TestClient(app)


@pytest.fixture
def mock_github_service():
    with patch("api.v1.github.routes.github_service") as mock_service:
        mock_service.get_accessible_repositories = AsyncMock()
        mock_service.get_repository_branches = AsyncMock()
        mock_service.validate_repository_access = AsyncMock()
        mock_service.client = AsyncMock()
        mock_service.client.get_installations = AsyncMock()
        yield mock_service


@pytest.mark.usefixtures("mock_auth")
class TestGitHubEndpoints:
    def test_get_organizations(self, client, mock_github_service):
        mock_github_service.client.get_installations.return_value = [
            {
                "id": 1,
                "account": {
                    "login": "org1",
                    "type": "Organization",
                    "avatar_url": "https://github.com/avatar.png",
                    "html_url": "https://github.com/org1",
                },
            }
        ]

        mock_github_service.get_accessible_repositories.return_value = [
            {
                "name": "repo1",
                "updatedAt": "2023-01-01T00:00:00Z",
                "private": False,
                "owner": "org1",
                "all_repos_access": False,
            },
            {
                "name": "repo2",
                "updatedAt": "2023-01-02T00:00:00Z",
                "private": True,
                "owner": "user1",
                "all_repos_access": False,
            },
        ]

        response = client.get("/api/v1/github/organizations")
        assert response.status_code == 200

        assert response.json() == {
            "success": True,
            "data": [
                {
                    "login": "testuser",
                    "type": "User",
                    "avatar_url": None,
                    "url": "https://github.com/testuser",
                },
                {
                    "login": "org1",
                    "type": "Organization",
                    "avatar_url": "https://github.com/avatar.png",
                    "url": "https://github.com/org1",
                },
                {"login": "user1", "type": "User", "avatar_url": None, "url": None},
            ],
        }

    def test_get_repositories(self, client, mock_github_service):
        mock_github_service.get_accessible_repositories.return_value = [
            {
                "name": "repo1",
                "updatedAt": "2023-01-01T00:00:00Z",
                "private": False,
                "owner": "testowner",
                "all_repos_access": False,
                "description": None,
            },
            {
                "name": "repo2",
                "updatedAt": "2023-01-02T00:00:00Z",
                "private": True,
                "owner": "testowner",
                "all_repos_access": False,
                "description": None,
            },
        ]

        response = client.get("/api/v1/github/repositories/testowner")
        assert response.status_code == 200
        assert response.json() == {
            "success": True,
            "data": [
                {
                    "name": "repo1",
                    "updatedAt": "2023-01-01T00:00:00Z",
                    "private": False,
                    "owner": "testowner",
                    "all_repos_access": False,
                    "description": None,
                },
                {
                    "name": "repo2",
                    "updatedAt": "2023-01-02T00:00:00Z",
                    "private": True,
                    "owner": "testowner",
                    "all_repos_access": False,
                    "description": None,
                },
            ],
        }

    def test_get_repository_branches(self, client, mock_github_service):
        mock_github_service.get_repository_branches.return_value = [
            {"name": "main", "isDefault": True},
            {"name": "develop", "isDefault": False},
        ]

        response = client.get("/api/v1/github/repository-branches/testowner/testrepo")
        assert response.status_code == 200
        assert response.json() == {
            "success": True,
            "data": [
                {"name": "main", "isDefault": True},
                {"name": "develop", "isDefault": False},
            ],
        }

    def test_validate_repository_accessible(self, client, mock_github_service):
        # Mock successful repository access
        mock_github_service.validate_repository_access.return_value = True

        response = client.get(
            "/api/v1/github/validate-repository?repo_url=https://github.com/owner/public-repo"
        )
        assert response.status_code == 200
        assert response.json() == {"success": True, "data": {"accessible": True}}

    def test_validate_repository_inaccessible(self, client, mock_github_service):
        # Mock inaccessible repository
        mock_github_service.validate_repository_access.side_effect = HTTPException(
            status_code=403,
            detail="This repository is private or inaccessible. Please make sure you have access to it.",
        )

        response = client.get(
            "/api/v1/github/validate-repository?repo_url=https://github.com/owner/private-repo"
        )
        assert response.status_code == 403
        assert response.json() == {
            "success": False,
            "code": 403,
            "message": "This repository is private or inaccessible. Please make sure you have access to it.",
            "details": None,
        }
