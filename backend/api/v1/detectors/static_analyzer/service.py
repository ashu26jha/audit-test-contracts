import os
import shutil
import tempfile
from typing import List, Optional

from fastapi import HTTPException

from api.v1.common.setup_environment import setup_environment
from api.v1.detectors.static_analyzer.helpers.aderyn import run_aderyn
from api.v1.detectors.static_analyzer.helpers.improve_slither_findings import (
    improve_slither_findings,
)
from api.v1.detectors.static_analyzer.helpers.slither import run_slither
from api.v1.detectors.static_analyzer.schema import StaticAnalysisOutput, StaticAnalyzerResponse
from core.schemas.scan_schema import SetupResult
from core.utils import logger


async def run_static_analyzer(
    github_url: str,
    oauth_token: str = None,
    selected_contracts: List[str] = None,
    setup_result: Optional[SetupResult] = None,
) -> StaticAnalyzerResponse:

    logger.info("[Static Analyzer] Starting static analyzer task...")

    try:
        # 1. Setup environment
        is_local_temp_dir = False
        temp_dir = setup_result.project_dir if setup_result else tempfile.mkdtemp()

        if setup_result is None:
            is_local_temp_dir = True
            setup_result: SetupResult = await setup_environment(
                github_url, temp_dir, oauth_token, contract_files=selected_contracts
            )

        # 2. Run Slither (with silent failure)
        try:
            slither_output = await run_slither(
                setup_result.project_dir, setup_result.remappings, selected_contracts
            )
            logger.info("[Static Analyzer] Slither analysis completed successfully")
        except Exception as e:
            logger.error(f"[Static Analyzer] Slither analysis failed: {str(e)}")
            slither_output = {"findings": [], "severity_counts": {}, "total_findings": 0}

        # 3. Run Aderyn (with silent failure)
        try:
            aderyn_output = await run_aderyn(setup_result.project_dir, selected_contracts)
            logger.info("[Static Analyzer] Aderyn analysis completed successfully")
        except Exception as e:
            logger.error(f"[Static Analyzer] Aderyn analysis failed: {str(e)}")
            aderyn_output = {"findings": [], "severity_counts": {}, "total_findings": 0}

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

        # 6. Create the final output with the improved findings
        static_analysis_output = StaticAnalysisOutput(
            total_findings=static_analysis_findings["total_findings"],
            severity_counts=static_analysis_findings["severity_counts"],
            findings=improved_findings,
        )

        # 7. Clean up the temporary directory if it was created locally
        if is_local_temp_dir and os.path.exists(temp_dir):
            shutil.rmtree(temp_dir)

        # Determine status message based on what succeeded
        status_message = ""
        if slither_output and aderyn_output:
            status_message = "Both Slither and Aderyn analyses completed successfully."
        elif slither_output:
            status_message = "Only Slither analysis completed successfully. Aderyn analysis failed."
        elif aderyn_output:
            status_message = "Only Aderyn analysis completed successfully. Slither analysis failed."

        logger.info(f"[Static Analyzer] {status_message}")

        return StaticAnalyzerResponse(
            message=status_message,
            status="Success",
            project_type=setup_result.project_type,
            environment_setup="Analysis completed successfully",
            static_analysis_output=static_analysis_output,
        )

    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e)) from e
    except Exception as e:
        raise HTTPException(
            status_code=500,
            detail=f"An unexpected error occurred during the analysis process: {str(e)}",
        ) from e
