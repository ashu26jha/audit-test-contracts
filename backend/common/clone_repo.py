import os
from typing import List, Optional, Union

from fastapi import HTTPException

from api.v1.helpers.run_command import run_command
from common import logger


async def clone_repo(
    repository_url: str,
    target_dir: str,
    access_token: Optional[str] = None,
    branch: str = "main",
) -> str:
    """
    Clones a repository into the specified directory.

    Args:
        repository_url (str): URL of the repository to clone
        target_dir (str): Directory where to clone the repository
        access_token (str, optional): GitHub access token for private repositories
        branch (str, optional): Branch to clone. Defaults to "main"

    Returns:
        str: Path to the cloned repository directory

    Raises:
        HTTPException: With appropriate status code and message for different failure scenarios
    """
    try:
        repo_dir = prepare_repo_directory(repository_url, target_dir)
        clone_cmd = prepare_clone_command(repository_url, repo_dir, access_token, branch)

        returncode, _, stderr = await run_command(clone_cmd, ".")
        if returncode != 0:
            handle_clone_error(stderr, access_token, branch)

        # Initialize and update submodules
        await run_command(
            ["git", "submodule", "update", "--init", "--recursive"],
            cwd=repo_dir,
        )

        logger.info(f"Successfully cloned repository from branch '{branch}' to {repo_dir}")
        return repo_dir

    except HTTPException:
        raise
    except Exception as e:
        safe_error = str(e)
        if access_token:
            safe_error = safe_error.replace(access_token, "***")
        logger.exception(f"Unexpected error during repository cloning: {safe_error}")
        raise HTTPException(status_code=500, detail="Internal Server Error")


def prepare_repo_directory(repository_url: str, target_dir: str) -> str:
    """Prepares the repository directory path."""
    repo_name = str(repository_url).split("/")[-1].replace(".git", "")
    return os.path.join(target_dir, repo_name)


def prepare_clone_command(
    repository_url: str, repo_dir: str, access_token: Optional[str], branch: str
) -> List[str]:
    """Prepares the git clone command with appropriate authentication."""

    CLONE_COMMAND = ["git", "clone", "--depth", "1", "--recurse-submodules", "-b", branch]

    if access_token:
        repository_url_with_auth = repository_url.replace("https://", f"https://{access_token}@")
        CLONE_COMMAND.extend([repository_url_with_auth, repo_dir])
    else:
        CLONE_COMMAND.extend([repository_url, repo_dir])

    return CLONE_COMMAND


def handle_clone_error(stderr: Union[str, bytes], access_token: Optional[str], branch: str) -> None:
    """Handles git clone errors and raises appropriate HTTP exceptions."""
    stderr_str = stderr.decode("utf-8") if isinstance(stderr, bytes) else stderr
    safe_stderr = stderr_str.replace(access_token, "***") if access_token else stderr_str

    if "Authentication failed" in stderr_str or "could not read Username" in stderr_str:
        raise HTTPException(
            status_code=401,
            detail="Unauthorized access to Git repository. Please check your access token.",
        )
    elif (
        f"Remote branch {branch} not found" in stderr_str
        or "did not match any file(s) known to git" in stderr_str
    ):
        raise HTTPException(
            status_code=404,
            detail=f"Branch '{branch}' not found in repository.",
        )
    elif "Repository not found" in stderr_str:
        raise HTTPException(
            status_code=404,
            detail="Repository not found. Please check the repository URL.",
        )
    else:
        logger.error(f"Git clone failed with error: {safe_stderr}")
        raise HTTPException(
            status_code=400,
            detail="Failed to clone repository. Please check the repository URL and authentication credentials.",
        )
