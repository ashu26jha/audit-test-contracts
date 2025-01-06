from pathlib import Path

from core.utils.logger import logger


async def save_fuzz_test(fuzz_test: str, project_dir: str) -> None:
    """
    Saves the provided fuzz test content to the test directory of the specified project.
    The function checks if a 'test' folder exists in the project directory and creates it
    if it does not. The fuzz test is saved as 'Test.t.sol'.

    Args:
        fuzz_test (str): The content of the fuzz test to be saved.
        project_dir (str): The directory of the project where the test folder is located.

    Raises:
        IOError: If there's an error writing the file to the disk.
    """
    logger.info("Saving fuzz test...")

    try:
        test_dir = Path(project_dir) / "test"
        test_dir.mkdir(parents=True, exist_ok=True)
        test_file_path = test_dir / "Test.t.sol"

        with open(test_file_path, "w", encoding="utf-8") as f:
            f.write(fuzz_test)

        logger.info(f"Fuzz test saved successfully at {test_file_path}.")

    except IOError as e:
        logger.error(f"Error saving fuzz test: {str(e)}")
        raise
