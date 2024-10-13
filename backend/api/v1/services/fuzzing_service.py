import shutil
import tempfile
from pathlib import Path
from typing import List, Optional

from api.v1.helpers.forge_helpers import read_file, update_foundry_config
from api.v1.helpers.project_helpers import get_project_structure
from api.v1.helpers.setup_environment_helpers import setup_environment
from api.v1.schemas.fuzzer_schema import FuzzerResponse, FuzzTestResult, SetupResult
from api.v1.schemas.static_analyzer_schema import SlitherOutput
from api.v1.services.fuzz_services.generate_fuzz_prompt import generate_fuzz_prompt
from api.v1.services.fuzz_services.generate_invariants import generate_invariants
from api.v1.services.fuzz_services.generate_report import generate_report
from api.v1.services.fuzz_services.get_fuzz_test import get_fuzz_test
from api.v1.services.fuzz_services.run_fuzz_file import run_fuzz_file
from common import logger
from common.profiles import Profiles
from config.prompts.fuzzer_prompts import SYSTEM_PROMPT_FUZZ_TEST


# TODO: filter findings by selected contracts
async def run_fuzzer(
    github_url: str,
    oauth_token: Optional[str] = None,
    selected_contracts: Optional[List[str]] = None,
    flattened_contracts: Optional[str] = None,
    setup_result: Optional[SetupResult] = None,
    slither_output: Optional[SlitherOutput] = None,
) -> FuzzerResponse:

    is_local_temp_dir = False

    # TODO: Different profiles for different fuzzing techniques?
    # for now both stateless and statefull (invariant) are in the same profile
    detected_profile = Profiles.FUZZING

    # TODO: Determine if system prompt should be used (right now it's always used)
    system_prompt = SYSTEM_PROMPT_FUZZ_TEST

    try:
        # 1. Setup the fuzzing environment (Handle standalone service)
        if setup_result is None:
            temp_dir = tempfile.mkdtemp()
            is_local_temp_dir = True
            try:
                setup_result: SetupResult = await setup_environment(
                    github_url, temp_dir, oauth_token
                )
            except Exception as e:
                logger.error(f"Failed to set up environment: {str(e)}")

        # Update project_dir to be from setup_result
        temp_dir = setup_result.project_dir
        contract_folders = setup_result.contract_folders
        project_path = setup_result.project_path
        project_type = setup_result.project_type
        project_structure = get_project_structure(temp_dir, contract_folders)

        # When called as a standalone service, flattened_contracts is not provided
        # TODO: limit tokens size? Remove interfaces?
        if flattened_contracts is None:
            project_dir_path = Path(project_path) / "src"

            all_contract_codes = ""
            for contract_file in project_dir_path.rglob("*.sol"):
                if "lib" not in contract_file.parts:
                    all_contract_codes += f"// {contract_file.relative_to(project_dir_path)}\n"
                    all_contract_codes += read_file(contract_file) + "\n"

            flattened_contracts = all_contract_codes

        # 2. Update Foundry configuration
        update_foundry_config(temp_dir)

        # 3. Generate the invarants
        invariants = await generate_invariants(
            detected_profile,
            project_structure,
            flattened_contracts,
            slither_output,
        )

        # 4. Generate the fuzz tests prompt
        fuzz_prompts = await generate_fuzz_prompt(
            project_dir=temp_dir,
            detected_profile=detected_profile,
            project_type=project_type,
            project_structure=project_structure,
            flattened_contracts=flattened_contracts,
            invariants=invariants,
            slither_output=slither_output,
        )

        # 5. Send the fuzz tests prompt to LLM for fuzz tests generation
        fuzz_test = await get_fuzz_test(
            fuzz_prompts,
            system_prompt,
            detected_profile,
            temp_dir,
            contract_folders,
            project_structure,
            str(invariants.invariants),
        )

        # 6. Run fuzz test
        fuzz_results = await run_fuzz_file(temp_dir)

        # 7. Generate report from tests
        report = await generate_report(fuzz_test, fuzz_results, contract_folders)

        report_json = FuzzTestResult(
            fuzz_test=fuzz_test,
            fuzz_results=fuzz_results,
            findings=report.findings,
        )

        if is_local_temp_dir:
            logger.info("Cleaning up environment")
            shutil.rmtree(temp_dir)

        logger.info(f"Fuzzing completed successfully with {len(report.findings)} findings.")

        return FuzzerResponse(
            message="Fuzzing completed successfully.",
            status="Success",
            data=report_json,
            error=None,
        )
    except Exception as e:
        return FuzzerResponse(
            message="An error occurred during the fuzzing process.",
            status="Error",
            data=None,
            error=str(e),
        )
