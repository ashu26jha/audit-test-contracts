from pathlib import Path

from api.v1.helpers.forge_helpers import read_file
from api.v1.schemas.fuzzer_schema import InvariantsList
from common import logger
from common.profiles import Profiles
from config.prompts.fuzzer_prompts import FUZZER_PROMPT_WITH_TEST, FUZZER_PROMPT_WITHOUT_TEST


async def generate_fuzz_prompt(
    project_dir: str,
    detected_profile: Profiles,
    project_type: str,
    project_structure: str,
    flattened_contracts: str,
    remappings: str,
    invariants: InvariantsList,
) -> str:
    """
    Generates a fuzzing prompt for the specified project directory by formatting the provided
    Solidity contract files, project structure, invariants, and optional Slither analysis output.
    The function checks for existing test cases and selects the appropriate prompt template based
    on the presence of a test folder.

    Args:
        project_dir (str): The project directory containing the Solidity contract files.
        detected_profile (Profiles): The detected profile, if any, used for context in generation.
        project_type (str): The type of the project (e.g., "foundry").
        project_structure (str): The structure of the project, detailing the organization of contracts.
        remappings (str): The remappings used in the project.
        flattened_contracts (str): The complete Solidity code of the contracts, flattened into a single string.
        invariants (InvariantsList): The invariants to be included in the prompt.

    Returns:
        str: The generated fuzzing prompt formatted for the LLM.
    """
    logger.info("Generating fuzz tests suite prompt...")

    existing_test_cases = ""

    # Check if the test folder exists
    test_folder_path = Path(project_dir) / "test"
    test_folder_exists = test_folder_path.exists() and test_folder_path.is_dir()
    logger.info(f"Test folder exists: {test_folder_exists}")

    # Check for existing test files in the test folder
    if test_folder_exists:
        for test_file in test_folder_path.rglob("*.t.sol"):
            existing_test_cases += f"// Existing test file: {test_file.relative_to(project_dir)}\n"
            existing_test_cases += read_file(test_file) + "\n"
        logger.info(
            f"Found {len(existing_test_cases.split('// Existing test file:')) - 1} existing test cases."
        )
    else:
        logger.info("No existing test cases found.")

    # Format invariants as a string list
    invariants_formatted = "\n".join(f"- {invariant}" for invariant in invariants.invariants)

    # Select the appropriate prompt based on the presence of a test folder
    if test_folder_exists and project_type.lower() == "foundry":
        logger.info("Using FUZZER_PROMPT_WITH_TEST")
        prompt = FUZZER_PROMPT_WITH_TEST.format(
            project_structure=project_structure,
            remappings=remappings,
            contract_code=flattened_contracts,
            existing_test_cases=existing_test_cases,
            invariants=invariants_formatted,
        )
    else:
        logger.info("Using FUZZER_PROMPT_WITHOUT_TEST")
        prompt = FUZZER_PROMPT_WITHOUT_TEST.format(
            project_structure=project_structure,
            remappings=remappings,
            contract_code=flattened_contracts,
            invariants=invariants_formatted,
        )

    return prompt
