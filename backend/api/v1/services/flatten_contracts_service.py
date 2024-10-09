import os
import subprocess
import tempfile
from typing import List

from common import logger
from fastapi import HTTPException


async def flatten_contracts(
    repository_url: str,
    contract_files: List[str],
    access_token: str,
    branch: str = "main",
):
    """
    Clones the repository and retrieves the specified contract files, flattening them into a single string.
    """
    with tempfile.TemporaryDirectory() as temp_dir:
        try:
            # Prepare clone command
            if access_token:
                # Use the auth token in the URL securely
                repository_url_with_auth = repository_url.replace(
                    "https://", f"https://{access_token}@"
                )
                clone_cmd = ["git", "clone", "-b", branch, repository_url_with_auth, temp_dir]
            else:
                clone_cmd = ["git", "clone", "-b", branch, repository_url, temp_dir]

            subprocess.run(clone_cmd, check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)

        except subprocess.CalledProcessError as e:
            stderr = e.stderr.decode("utf-8") if e.stderr else ""
            if "Authentication failed" in stderr or "fatal: could not read Username" in stderr:
                message = "Unauthorized access to Git repository. Please check your access token."
                logger.error(message)
                raise HTTPException(status_code=401, detail=message)
            else:
                message = f"Failed to clone repository: {stderr}"
                logger.error(message)
                raise HTTPException(
                    status_code=400,
                    detail="Failed to clone repository. Please check the repository URL and authentication credentials.",
                )

        except Exception as e:
            message = f"An unexpected error occurred while flattening contracts: {str(e)}"
            logger.error(message)
            raise HTTPException(status_code=500, detail="Internal Server Error")

        # Read and concatenate the contract files
        flattened_code = ""
        for file_path in contract_files:
            full_path = os.path.join(temp_dir, file_path)
            if not os.path.isfile(full_path):
                message = f"Contract file '{file_path}' not found in repository."
                logger.error(message)
                raise HTTPException(status_code=404, detail=message)
            with open(full_path, "r", encoding="utf-8") as f:
                flattened_code += f"// File: {file_path}\n"
                flattened_code += f.read() + "\n\n"

        return flattened_code
