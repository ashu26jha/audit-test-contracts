import os
from pathlib import Path

async def save_fuzz_test(fuzz_test: str, project_dir: str) -> None:
    """
    Saves the fuzz test to the test directory of the project.

    Args:
        fuzz_test (str): The content of the fuzz test.
        project_dir (str): The directory of the project.

    Raises:
        IOError: If there's an error writing the file.
    """
    try:
        test_dir = Path(project_dir) / "test"
        test_file_path = test_dir / "Test.t.sol"

        # Ensure the test directory exists
        test_dir.mkdir(parents=True, exist_ok=True)

        # Write the fuzz test to the file
        with open(test_file_path, "w") as f:
            f.write(fuzz_test)
        # print(f"Fuzz test saved successfully at {test_file_path}") # Debugging
    except IOError as e:
        print(f"Error saving fuzz test: {str(e)}")
        raise