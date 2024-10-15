import shutil
import tempfile
from typing import List, Optional

from api.v1.helpers.improve_slither_findings_helpers import improve_slither_findings
from api.v1.helpers.setup_environment_helpers import setup_environment
from api.v1.helpers.slither_helpers import run_slither
from api.v1.schemas.fuzzer_schema import SetupResult
from api.v1.schemas.static_analyzer_schema import SlitherOutput, StaticAnalyzerResponse
from common import logger


async def run_static_analyzer(
    github_url: str,
    oauth_token: str = None,
    selected_contracts: List[str] = None,
    setup_result: Optional[SetupResult] = None,
) -> StaticAnalyzerResponse:

    # 1. Setup environment
    is_local_temp_dir = False
    temp_dir = setup_result.project_dir if setup_result else tempfile.mkdtemp()

    if setup_result is None:
        is_local_temp_dir = True
        setup_result: SetupResult = await setup_environment(github_url, temp_dir, oauth_token)

    # 2. Run Slither
    slither_output = await run_slither(
        setup_result.project_dir, setup_result.remappings, selected_contracts
    )

    # 3. Improve Slither descriptions
    if slither_output and "findings" in slither_output and len(slither_output["findings"]) > 0:
        logger.info(
            f"Improving Slither descriptions for {len(slither_output['findings'])} findings..."
        )

        improved_findings = await improve_slither_findings(slither_output["findings"])
        slither_output["findings"] = improved_findings

    # 4. Remove temporary directory if created locally
    if is_local_temp_dir:
        shutil.rmtree(temp_dir)

    logger.info(f"Slither completed successfully with {len(slither_output['findings'])} findings.")

    return StaticAnalyzerResponse(
        message="Repository analyzed successfully.",
        status="Success",
        project_type=setup_result.project_type,
        environment_setup="Analysis completed successfully",
        slither_output=SlitherOutput(**slither_output),
    )
