import os
import shutil
import tempfile
from typing import Any, Dict, List, Optional, Tuple

from api.v1.common.setup_environment import setup_environment
from api.v1.detectors.context_scan.schema import FindingList
from api.v1.detectors.static_analyzer.helpers.aderyn import run_aderyn
from api.v1.detectors.static_analyzer.helpers.improve_slither_findings import (
    improve_slither_findings,
)
from api.v1.detectors.static_analyzer.helpers.slither import run_slither
from core.schemas.scan_schema import SetupResult
from core.utils import logger
from core.utils.errors import DetectorError


async def run_static_analyzer(
    github_url: str,
    oauth_token: str = None,
    selected_contracts: List[str] = None,
    setup_result: Optional[SetupResult] = None,
) -> FindingList:
    """
    Run static analyzers (Slither and Aderyn) on smart contracts.

    Args:
        github_url: URL of the GitHub repository
        oauth_token: Optional OAuth token for private repositories
        selected_contracts: List of contract files to analyze
        setup_result: Optional setup result from a previous operation

    Returns:
        FindingList containing the static analysis findings

    Raises:
        DetectorError: If both analyzers fail or if there's a critical error in the setup
    """
    logger.info("[Static Analyzer] Starting static analyzer task...")

    try:
        # 1. Setup environment
        is_local_temp_dir = False
        temp_dir = setup_result.project_dir if setup_result else tempfile.mkdtemp()

        if setup_result is None:
            is_local_temp_dir = True
            setup_result = await _handle_environment_setup(
                github_url, temp_dir, oauth_token, selected_contracts
            )

        # 2. Run Slither (with silent failure)
        slither_output, slither_succeeded = await _handle_slither_analysis(
            setup_result.project_dir, setup_result.remappings, selected_contracts
        )

        # 3. Run Aderyn (with silent failure)
        aderyn_output, aderyn_succeeded = await _handle_aderyn_analysis(
            setup_result.project_dir, selected_contracts
        )

        # If both analyzers failed, raise an error
        if not slither_succeeded and not aderyn_succeeded:
            logger.error("[Static Analyzer] Both Slither and Aderyn analyses failed")
            raise DetectorError("Both static analyzers (Slither and Aderyn) failed to run")

        # 4. Combine Slither and Aderyn outputs
        slither_output["severity_counts"]["High"] = slither_output["severity_counts"].get(
            "High", 0
        ) + aderyn_output["severity_counts"].get("High", 0)
        slither_output["severity_counts"]["Low"] = slither_output["severity_counts"].get(
            "Low", 0
        ) + aderyn_output["severity_counts"].get("Low", 0)

        # Log the number of findings from each source
        logger.info(f"[Static Analyzer] Slither found {len(slither_output['findings'])} findings")
        logger.info(f"[Static Analyzer] Aderyn found {len(aderyn_output['findings'])} findings")

        static_analysis_findings = {
            "findings": slither_output["findings"] + aderyn_output["findings"],
            "total_findings": len(slither_output["findings"]) + len(aderyn_output["findings"]),
            "severity_counts": slither_output["severity_counts"],
        }

        # 5. Improve the descriptions of the findings
        improved_findings = await improve_slither_findings(static_analysis_findings["findings"])

        # 6. Clean up the temporary directory if it was created locally
        if is_local_temp_dir and os.path.exists(temp_dir):
            shutil.rmtree(temp_dir)

        # Determine status message based on what succeeded
        status_message = ""
        if slither_succeeded and aderyn_succeeded:
            status_message = "Both Slither and Aderyn analyses completed successfully."
        elif slither_succeeded:
            status_message = "Only Slither analysis completed successfully. Aderyn analysis failed."
        elif aderyn_succeeded:
            status_message = "Only Aderyn analysis completed successfully. Slither analysis failed."

        logger.info(f"[Static Analyzer] {status_message}")

        return FindingList(findings=improved_findings)

    except DetectorError:
        # Re-raise detector errors to be handled by caller
        raise
    except Exception as e:
        logger.error(f"[Static Analyzer] An unexpected error occurred: {str(e)}", exc_info=True)
        raise DetectorError(f"Static analyzer failed: {str(e)}") from e


async def _handle_environment_setup(
    github_url: str, temp_dir: str, oauth_token: str, contract_files: List[str]
) -> SetupResult:
    try:
        setup_result: SetupResult = await setup_environment(
            github_url, temp_dir, oauth_token, contract_files=contract_files
        )
        return setup_result
    except Exception as e:
        logger.error(f"[Static Analyzer] Environment setup failed: {str(e)}")
        raise DetectorError(f"Failed to setup environment: {str(e)}") from e


async def _handle_slither_analysis(
    project_dir: str, remappings: List[str], selected_contracts: List[str]
) -> Tuple[Dict[str, Any], bool]:
    slither_succeeded = False
    try:
        slither_output = await run_slither(project_dir, remappings, selected_contracts)
        slither_succeeded = True
        logger.info("[Static Analyzer] Slither analysis completed successfully")
    except Exception as e:
        logger.error(f"[Static Analyzer] Slither analysis failed: {str(e)}")
        slither_output = {"findings": [], "severity_counts": {}, "total_findings": 0}

    return slither_output, slither_succeeded


async def _handle_aderyn_analysis(
    project_dir: str, selected_contracts: List[str]
) -> Tuple[Dict[str, Any], bool]:
    aderyn_succeeded = False
    try:
        aderyn_output = await run_aderyn(project_dir, selected_contracts)
        aderyn_succeeded = True
        logger.info("[Static Analyzer] Aderyn analysis completed successfully")
    except Exception as e:
        logger.error(f"[Static Analyzer] Aderyn analysis failed: {str(e)}")
        aderyn_output = {"findings": [], "severity_counts": {}, "total_findings": 0}

    return aderyn_output, aderyn_succeeded
