import os
import tempfile

import pytest

from api.v1.common.setup_environment import setup_environment
from core.schemas.audit_agent_schema import SetupResult
from core.utils.logger import logger
from tests.setup_environment.repo_samples import TEST_REPOS, RepoConfig


class TestSetupEnvironment:
    """Test suite for setup_environment functionality"""

    @pytest.fixture(params=TEST_REPOS)
    def repo(self, request) -> RepoConfig:
        """Fixture to provide test repositories one at a time"""
        return request.param

    @pytest.mark.asyncio
    async def test_repo(self, repo: RepoConfig):
        """Test repository setup and compilation"""
        logger.info(f"Starting test for repository: {repo.url}")
        with tempfile.TemporaryDirectory() as temp_dir:
            try:
                logger.info(f"\nTesting {repo.description}")
                logger.info(f"Repository: {repo.url}")
                logger.info(f"Project type: {repo.project_type}")

                setup_result = await setup_environment(
                    github_url=repo.url,
                    temp_dir=temp_dir,
                    branch=repo.branch,
                    contract_files=repo.contract_paths,
                )

                assert setup_result is not None, "Setup failed"
                assert isinstance(setup_result, SetupResult), "Invalid setup result type"
                assert setup_result.project_type == repo.project_type, "Wrong project type detected"

                if repo.expected_root:
                    # Normalize paths to handle different OS path separators
                    expected_root_normalized = os.path.normpath(repo.expected_root)
                    project_dir_normalized = os.path.normpath(setup_result.project_dir)

                    assert project_dir_normalized.endswith(
                        expected_root_normalized
                    ), f"Wrong project root detected: expected ending with '{expected_root_normalized}', but got '{project_dir_normalized}'"

                assert os.path.exists(
                    os.path.join(setup_result.project_dir, "out")
                ), "Compilation output directory not found"

                logger.info("✅ Test passed\n")

            except Exception as e:
                logger.error(f"❌ Test failed: {str(e)}\n")
                raise


if __name__ == "__main__":
    """Manual test runner"""
    pytest.main(["-v", "--log-cli-level=DEBUG", __file__])
