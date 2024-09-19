import asyncio
from pathlib import Path
from api.v1.prompts.fuzzer_prompts import FUZZER_PROMPT
from api.v1.documentation.fuzz_testing import FUZZ_TESTING
from api.v1.documentation.fuzz_examples import FUZZ_EXAMPLES

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

async def generate_fuzz_prompts(project_dir: str) -> str:
    """
    Generates the fuzzing prompt for the given project directory by reading all Solidity contract files
    in the /src directory and formatting them with the provided documentation and examples.

    Args:
        project_dir (str): The project directory containing the Solidity contract files.

    Returns:
        str: The generated fuzzing prompt.
    """

    # Find all files in the /src directory and read their content
    src_dir = Path(project_dir) / "src"
    contract_code = ""
    for file_path in src_dir.glob("*.sol"):
        contract_code += await asyncio.to_thread(read_file, file_path)

    return FUZZER_PROMPT.format(
        contract_code=contract_code,
        docs=FUZZ_TESTING,
        fuzz_examples=FUZZ_EXAMPLES
    )
