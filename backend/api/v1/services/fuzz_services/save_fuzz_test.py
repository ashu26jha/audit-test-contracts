from pathlib import Path
from typing import List

from common import logger


async def save_fuzz_test(fuzz_test: str, project_dir: str, contract_folders: List[str]) -> None:
    """
    Saves the provided fuzz test content to the test directory of the specified project.
    The function checks if a 'test' folder exists in the project directory and creates it
    if it does not. The fuzz test is saved as 'Test.t.sol'.

    Args:
        fuzz_test (str): The content of the fuzz test to be saved.
        project_dir (str): The directory of the project where the test folder is located.
        contract_folders (List[str]): List of contract folders in the project, used to determine
                                       if the 'test' folder needs to be created.

    Raises:
        IOError: If there's an error writing the file to the disk.
    """
    logger.info("Saving fuzz test...")

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

    except IOError as e:
        logger.error(f"Error saving fuzz test: {str(e)}")
        raise
