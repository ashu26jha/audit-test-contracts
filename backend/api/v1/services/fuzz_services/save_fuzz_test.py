from pathlib import Path
from typing import List

from api.v1.helpers.project_helpers import compile_project
from common import logger


async def save_fuzz_test(
    fuzz_test: str, project_dir: str, contract_folders: List[str], solc_version: str
) -> None:
    """
    Saves the fuzz test to the test directory of the project.

    Args:
        fuzz_test (str): The content of the fuzz test.
        project_dir (str): The directory of the project.
        contract_folders (List[str]): List of contract folders in the project.

    Raises:
        IOError: If there's an error writing the file.
    """
    try:
        # Check if 'test' folder is in contract_folders
        if "test" not in contract_folders:
            test_dir = Path(project_dir) / "test"
            test_dir.mkdir(parents=True, exist_ok=True)
        else:
            test_dir = Path(project_dir) / "test"

        test_file_path = test_dir / "Test.t.sol"

        with open(test_file_path, "w") as f:
            f.write(fuzz_test)

        await compile_project(project_dir)

    except IOError as e:
        logger.error(f"Error saving fuzz test: {str(e)}")
        raise
