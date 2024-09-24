import asyncio
from pathlib import Path
from typing import List
from api.v1.prompts.fuzzer_prompts import FUZZER_PROMPT
from api.v1.documentation.fuzz_testing import FUZZ_TESTING
from api.v1.documentation.fuzz_examples import FUZZ_EXAMPLES
from api.v1.utils.project_helpers import get_project_structure
def read_file(path: str) -> str:
    """
    Reads the content of a file.

    Args:
        path (str): The file path.

    Returns:
        str: The content of the file.
    """
    with open(path, 'r') as file:
        return file.read()

async def generate_fuzz_prompts(project_dir: str, contract_folders: List[str]) -> str:
    """
    Generates the fuzzing prompt for the given project directory by reading all Solidity contract files
    in the specified contract folders and formatting them with the provided documentation and examples.

    Args:
        project_dir (str): The project directory containing the Solidity contract files.
        contract_folders (List[str]): List of folders containing the contract files.

    Returns:
        str: The generated fuzzing prompt.
    """
    all_contract_codes = ""

    for folder in contract_folders:
        folder_path = Path(project_dir) / folder
        for contract_file in folder_path.rglob("*.sol"):
            all_contract_codes += f"// {contract_file.relative_to(project_dir)}\n"
            all_contract_codes += read_file(contract_file) + "\n"

    project_structure = get_project_structure(project_dir, contract_folders)

    return FUZZER_PROMPT.format(
        contract_code=all_contract_codes,
        docs=FUZZ_TESTING,
        fuzz_examples=FUZZ_EXAMPLES,
        project_structure=project_structure
    )