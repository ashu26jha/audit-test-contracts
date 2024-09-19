import asyncio
import os
import tempfile
import uuid
import shutil
from typing import Tuple
from pathlib import Path

async def setup_environment(
    contracts: str,
    contract_name: str
) -> Tuple[str, str]:
    """
    Sets up the environment by creating a virtual environment, initializing a Foundry project,
    and adding the contract to the src directory. Also removes Counter.sol, Counter.t.sol, and Counter.s.sol files.

    Args:
        contracts (str): The Solidity contract code to be added.
        contract_name (str): The name of the Solidity contract file.

    Returns:
        Tuple[str, str]: The project directory and contract name.
    """
    try:
        # Generate a random project directory name
        project_dir = tempfile.mkdtemp(prefix="fuzz_project_")
        project_path = Path(project_dir)
        
        # 1. Create project directory if it doesn't exist
        project_path.mkdir(parents=True, exist_ok=True)
        # print(f"Project directory '{project_dir}' is ready.") # Debugging
        
        # NOTE: This is just a folder, not a virtual environment.

        # 4. Initialize Foundry project with the specified template
        print("Initializing Foundry project...")
        process = await asyncio.create_subprocess_exec(
            "forge", "init", "--template", "DanielBoye/foundry-template", str(project_path),
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE
        )
        stdout, stderr = await process.communicate()
        if process.returncode != 0:
            raise Exception(f"Failed to initialize Foundry project: {stderr.decode().strip()}")
        print("Foundry project initialized.")

        # 5. Remove Counter.sol, Counter.t.sol, and Counter.s.sol files if they exist
        counter_files = [
            project_path / "src" / "Counter.sol",
            project_path / "test" / "Counter.t.sol",
            project_path / "script" / "Counter.s.sol"
        ]
        for file_path in counter_files:
            if file_path.exists():
                file_path.unlink()
                # print(f"Removed {file_path}") # Debugging

        # 5. Add the contract code to src directory
        src_dir = project_path / "src"
        src_dir.mkdir(parents=True, exist_ok=True)
        contract_path = src_dir / contract_name
        # print(f"Adding contract to '{contract_path}'...") # Debugging
        await asyncio.to_thread(write_file, contract_path, contracts)
        # print("Contract added successfully.") # Debugging

        # TODO: Should we create an empty TestContract.t.sol file in the test directory
        # that will be later written with the fuzz test?
        # NOTE: This is done in the run_fuzz function.
        print("Virtual environment created, Foundry project initialized, and contract added successfully.")

        return project_dir, contract_name

    except Exception as e:
        print(f"Error setting up environment: {str(e)}")
        if project_dir and os.path.exists(project_dir):
            shutil.rmtree(project_dir)
        raise

def write_file(path: Path, content: str) -> None:
    """
    Writes the given content to the specified file path.

    Args:
        path (Path): The file path where the content will be written.
        content (str): The content to write to the file.
    """
    with open(path, 'w') as f:
        f.write(content)
