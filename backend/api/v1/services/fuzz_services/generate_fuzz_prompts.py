from pathlib import Path
from typing import List

from api.v1.helpers.project_helpers import get_project_structure
from api.v1.schemas.static_analyzer_schema import SlitherOutput
from common import logger
from common.profiles import Profiles
from config.prompts.fuzzer_prompts import FUZZER_PROMPT_WITH_TEST, FUZZER_PROMPT_WITHOUT_TEST


def read_file(path: str) -> str:
    """
    Reads the content of a file.

    Args:
        path (str): The file path.

    Returns:
        str: The content of the file.
    """
    with open(path, "r") as file:
        return file.read()


async def generate_fuzz_prompts(
    project_dir: str,
    contract_folders: List[str],
    slither_output: SlitherOutput,
    detected_profile: Profiles,
    project_type: str,
    invariants: List[dict],
) -> str:
    """
    Generates the fuzzing prompt for the given project directory by reading all Solidity contract files
    in the specified contract folders and formatting them with the provided documentation, examples, and Slither output.

    Args:
        project_dir (str): The project directory containing the Solidity contract files.
        contract_folders (List[str]): List of folders containing the contract files.
        slither_output (SlitherOutput): The output from Slither analysis.

    Returns:
        str: The generated fuzzing prompt.
    """
    all_contract_codes = ""
    existing_test_cases = ""
    findings_str = ""

    # Check if the test folder exists
    test_folder_path = Path(project_dir) / "test"
    test_folder_exists = test_folder_path.exists() and test_folder_path.is_dir()

    if slither_output is None:
        findings_str = ""
    else:
        # Access findings from slither_output
        findings = slither_output.findings

        # Process findings and convert them to a string format
        for finding in findings:
            findings_str += f"Issue: {finding.Issue}\n"
            findings_str += f"Original Issue: {finding.OriginalIssue}\n"
            findings_str += f"Severity: {finding.Severity}\n"
            findings_str += f"Confidence: {finding.Confidence}\n"
            findings_str += f"Contracts: {', '.join(finding.Contracts)}\n"
            findings_str += f"Description: {finding.Description}\n"
            findings_str += f"Lines: {finding.Lines}\n\n"

    if project_type == "hardhat":
        contract_folders = ["contracts"]

    # Convert project_dir to a Path object and add 'src' to it since it is now a Foundry project
    project_dir_path = Path(project_dir) / "src"

    for folder in contract_folders:
        folder_path = project_dir_path / folder
        for contract_file in folder_path.rglob("*.sol"):
            if "lib" not in contract_file.parts:
                all_contract_codes += f"// src/{contract_file.relative_to(project_dir_path)}\n"
                all_contract_codes += read_file(contract_file) + "\n"
    # Check for existing test files in the test folder
    if test_folder_exists:
        for test_file in test_folder_path.rglob("*.t.sol"):
            existing_test_cases += f"// Existing test file: {test_file.relative_to(project_dir)}\n"
            existing_test_cases += read_file(test_file) + "\n"

    project_structure = get_project_structure(project_dir, contract_folders)

    # Convert invariants to a string format for the prompt
    invariants_str = "\n".join(
        f"- {invariant['description']} (Function: {invariant['function']}, Condition: {invariant['condition']})"
        for invariant in invariants
    )

    # Select the appropriate prompt based on the presence of a test folder
    if test_folder_exists and project_type == "foundry":
        logger.info("Using FUZZER_PROMPT_WITH_TEST")
        prompt = FUZZER_PROMPT_WITH_TEST.format(
            contract_code=all_contract_codes,
            project_structure=project_structure,
            slither_output=findings_str,
            existing_test_cases=existing_test_cases,
            invariants=invariants_str,
        )
    else:
        logger.info("Using FUZZER_PROMPT_WITHOUT_TEST")
        prompt = FUZZER_PROMPT_WITHOUT_TEST.format(
            contract_code=all_contract_codes,
            project_structure=project_structure,
            slither_output=findings_str,
            invariants=invariants_str,
        )

    return prompt
