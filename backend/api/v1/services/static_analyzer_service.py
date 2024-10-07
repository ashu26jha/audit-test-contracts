import shutil
import tempfile
from typing import List, Optional

from api.v1.schemas.fuzzer_schema import SetupResult
from api.v1.schemas.static_analyzer_schema import SlitherOutput, StaticAnalyzerResponse
from api.v1.utils.slither_helpers import run_slither
from common import logger
from common.setup_environment import setup_environment


async def run_static_analyzer(
    github_url: str,
    oauth_token: str = None,
    selected_contracts: List[str] = None,
    temp_dir: Optional[str] = None,
) -> StaticAnalyzerResponse:
    logger.info(f"Starting static analysis for repository: {github_url}")

    # 1. Setup environment
    is_local_temp_dir = False
    if temp_dir is None:
        temp_dir = tempfile.mkdtemp()
        is_local_temp_dir = True
    setup_result: SetupResult = await setup_environment(github_url, oauth_token, temp_dir)
    logger.info(f"Project type: {setup_result.project_type}")

    # 2. Run Slither
    slither_output = await run_slither(
        setup_result.project_dir, setup_result.remappings, selected_contracts
    )

    if is_local_temp_dir:
        shutil.rmtree(temp_dir)

    return StaticAnalyzerResponse(
        message="Repository analyzed successfully.",
        status="Success",
        project_type=setup_result.project_type,
        contract_folders=setup_result.contract_folders,
        environment_setup="Analysis completed successfully",
        slither_output=SlitherOutput(**slither_output),
    )
