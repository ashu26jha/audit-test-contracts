from pathlib import Path


def check_for_test_folder(temp_dir: str) -> bool:
    test_folder_path = Path(temp_dir) / "test"
    return test_folder_path.exists() and test_folder_path.is_dir()
