import os
import subprocess
import tempfile
from typing import List

from common import logger
from common.exceptions import InternalServerError, ValidationError


async def flatten_contracts(
    repository_url: str,
    contractFiles: List[str],
    auth_token: str,
) -> str:
    """
    Clones the repository and retrieves the specified contract files, flattening them into a single string.

    Args:
        repository_url (str): The URL of the GitHub repository.
        contractFiles (List[str]): List of relative file paths within the repository.
        auth_token (str): Authentication token for private repositories.

    Returns:
        str: Concatenated content of all specified contract files.

    Raises:
        ValueError: If cloning fails or if a specified file is not found.
    """
    with tempfile.TemporaryDirectory() as temp_dir:
        try:
            # Prepare clone command
            if auth_token:
                # Use the auth token in the URL securely
                repository_url_with_auth = repository_url.replace(
                    "https://", f"https://{auth_token}@"
                )
                clone_cmd = ["git", "clone", repository_url_with_auth, temp_dir]
            else:
                clone_cmd = ["git", "clone", repository_url, temp_dir]

            subprocess.run(clone_cmd, check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)

        except subprocess.CalledProcessError as e:
            logger.error(f"Failed to clone repository: {str(e)}")
            raise ValidationError(
                "Failed to clone repository. Please check the repository URL and authentication token."
            )
        except FileNotFoundError as e:
            logger.error(f"Contract file not found: {str(e)}")
            raise ValidationError(f"Contract file '{e.filename}' not found in repository.")
        except Exception as e:
            logger.error(f"Unexpected error in flatten_contracts: {str(e)}")
            raise InternalServerError("An error occurred while flattening contracts") from e

        # Read and concatenate the contract files
        flattened_code = ""
        for file_path in contractFiles:
            full_path = os.path.join(temp_dir, file_path)
            if not os.path.isfile(full_path):
                raise ValueError(f"Contract file '{file_path}' not found in repository.")
            with open(full_path, "r") as f:
                flattened_code += f"// File: {file_path}\n"
                flattened_code += f.read() + "\n\n"

        return flattened_code
