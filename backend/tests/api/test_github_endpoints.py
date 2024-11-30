from unittest.mock import AsyncMock, patch

import pytest
from fastapi.testclient import TestClient

from main import app


@pytest.fixture(scope="module")
def client():
    return TestClient(app)


@pytest.fixture
def mock_github_service():
    with patch("api.v1.endpoints.github.github_service") as mock_service:
        mock_service.get_user_organizations_and_personal = AsyncMock()
        mock_service.get_repositories = AsyncMock()
        mock_service.get_repository_branches = AsyncMock()
        mock_service.check_repository_access = AsyncMock()
        mock_service.get_accessible_repositories = AsyncMock()
        yield mock_service


@pytest.mark.usefixtures("mock_auth")
class TestGitHubEndpoints:
    def test_get_organizations(self, client, mock_github_service):
        mock_github_service.get_accessible_repositories.return_value = [
            {"owner": "org1", "type": "organization"},
            {"owner": "user1", "type": "user"},
        ]

        response = client.get("/api/v1/github/organizations")
        assert response.status_code == 200
        assert response.json() == {
            "success": True,
            "data": [{"login": "org1", "type": "user"}, {"login": "user1", "type": "user"}],
        }

    def test_get_repositories(self, client, mock_github_service):
        mock_github_service.get_accessible_repositories.return_value = [
            {
                "name": "repo1",
                "updatedAt": "2023-01-01T00:00:00Z",
                "private": False,
                "owner": "testowner",
            },
            {
                "name": "repo2",
                "updatedAt": "2023-01-02T00:00:00Z",
                "private": True,
                "owner": "testowner",
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
                },
                {
                    "name": "repo2",
                    "updatedAt": "2023-01-02T00:00:00Z",
                    "private": True,
                    "owner": "testowner",
                },
            ],
        }

    def test_get_repository_branches(self, client, mock_github_service):
        mock_github_service.get_repository_branches.return_value = ["main", "develop"]

        response = client.get("/api/v1/github/repository-branches/testowner/testrepo")
        assert response.status_code == 200
        assert response.json() == {"success": True, "data": ["main", "develop"]}

    def test_validate_repo_url(self, client, mock_github_service):
        mock_github_service.check_repository_access.return_value = {
            "name": "testrepo",
            "owner": {"login": "testowner"},
            "default_branch": "main",
        }

        response = client.get(
            "/api/v1/github/validate-repo-url?repo_url=https://github.com/testowner/testrepo"
        )
        assert response.status_code == 200
        assert response.json() == {
            "success": True,
            "data": {
                "repo_name": "testrepo",
                "owner": "testowner",
                "default_branch": "main",
                "repo_url": "https://github.com/testowner/testrepo",
            },
        }
