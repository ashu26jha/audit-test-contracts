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
from core.schemas.audit_agent_schema import SetupResult


async def run_static_analyzer(
    github_url: str,
    oauth_token: str = None,
    selected_contracts: List[str] = None,
    setup_result: Optional[SetupResult] = None,
) -> StaticAnalyzerResponse:

    try:
        # 1. Setup environment
        is_local_temp_dir = False
        temp_dir = setup_result.project_dir if setup_result else tempfile.mkdtemp()

        if setup_result is None:
            is_local_temp_dir = True
            setup_result: SetupResult = await setup_environment(
                github_url, temp_dir, oauth_token, contract_files=selected_contracts
            )

        # 2. Run Slither
        slither_output = await run_slither(
            setup_result.project_dir, setup_result.remappings, selected_contracts
        )

        # 3. Run Aderyn
        aderyn_output = await run_aderyn(setup_result.project_dir, selected_contracts)

        # 4. Combine Slither and Aderyn outputs
        slither_output["severity_counts"]["High"] = slither_output["severity_counts"].get(
            "High", 0
        ) + aderyn_output["severity_counts"].get("High", 0)
        slither_output["severity_counts"]["Low"] = slither_output["severity_counts"].get(
            "Low", 0
        ) + aderyn_output["severity_counts"].get("Low", 0)

        static_analysis_findings = {
            "findings": slither_output["findings"] + aderyn_output["findings"],
            "total_findings": len(slither_output["findings"]) + len(aderyn_output["findings"]),
            "severity_counts": slither_output["severity_counts"],
        }

        # 5. Improve Static Analysis descriptions
        if (
            static_analysis_findings
            and "findings" in static_analysis_findings
            and len(static_analysis_findings["findings"]) > 0
        ):
            static_analysis_findings["findings"] = await improve_slither_findings(
                static_analysis_findings["findings"]
            )
            static_analysis_findings["total_findings"] = len(static_analysis_findings["findings"])

        # 6. Remove temporary directory if created locally
        if is_local_temp_dir:
            shutil.rmtree(temp_dir)

        return StaticAnalyzerResponse(
            message="Repository analyzed successfully.",
            status="Success",
            project_type=setup_result.project_type,
            environment_setup="Analysis completed successfully",
            static_analysis_output=StaticAnalysisOutput(**static_analysis_findings),
        )
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e)) from e
    except Exception as e:
        raise HTTPException(
            status_code=500,
            detail=f"An unexpected error occurred during the analysis process: {str(e)}",
        ) from e
