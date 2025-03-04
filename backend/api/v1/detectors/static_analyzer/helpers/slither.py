import json
import os
import re
from typing import Any, Dict, List, Optional

from api.v1.common.contract_utils import filter_by_contracts
from api.v1.detectors.static_analyzer.helpers.slither_detectors_titles import SLITHER_DETECTOR_MAP
from config.solidity_settings import CONFIDENCE_LEVELS
from core.models.scan import Finding
from core.utils.logger import logger
from core.utils.run_command import run_command
from core.utils.severity import Severity


def extract_contract_from_lines(lines: str) -> str:
    match = re.search(r"src/(.+?)\.sol", lines)
    if match:
        return match.group(1) + ".sol"
    return ""


def transform_slither_output(
    slither_output: Dict[str, Any], selected_contracts: List[str]
) -> Dict[str, Any]:
    transformed_results = []
    severity_counts = {
        "High": 0,
        "Medium": 0,
        "Low": 0,
        "Informational": 0,
        "Optimization": 0,
    }
    total_findings = 0

    if "results" in slither_output and "detectors" in slither_output["results"]:
        for detector in slither_output["results"]["detectors"]:
            confidence = detector.get("confidence", "").lower()

            # Filter findings based on confidence level
            if confidence.lower() not in CONFIDENCE_LEVELS:
                continue

            severity = detector.get("impact", "")
            lines = detector.get("first_markdown_element", "")

            contract = extract_contract_from_lines(lines)
            contracts = [contract] if contract else []

            # Use the SLITHER_DETECTOR_MAP with fallback to original issue
            original_issue = detector.get("check", "")
            mapped_issue = SLITHER_DETECTOR_MAP.get(original_issue, {})

            # Get the title and description from the mapped issue
            issue_title = mapped_issue.get("title", original_issue)
            custom_description = mapped_issue.get("description", "")

            # Combine custom description with Slither's description
            full_description = f"{custom_description}\n\n{detector.get('description', '')}"

            # Convert dict to Finding model before filtering
            transformed_result = Finding(
                Issue=issue_title,
                Severity=Severity.validate(severity),
                Contracts=contracts,
                Description=full_description,
                Recommendation="",
            )
            transformed_results.append(transformed_result)

    # Use the common filtering function
    filtered_results = filter_by_contracts(
        transformed_results, selected_contracts, contract_field="Contracts"
    )

    # Count severities and total findings after filtering
    for result in filtered_results:
        severity = result.Severity.value if hasattr(result.Severity, "value") else result.Severity
        if severity in severity_counts:
            severity_counts[severity] += 1
        elif severity == "Info":
            severity_counts["Informational"] += 1
        elif severity == "Best Practices":
            severity_counts["Optimization"] += 1
        total_findings += 1

    return {
        "findings": filtered_results,  # Return Finding objects directly
        "severity_counts": severity_counts,
        "total_findings": total_findings,
    }


async def run_slither(
    temp_dir: str,
    remappings: Optional[List[str]] = None,
    selected_contracts: List[str] = [],
) -> Dict[str, Any]:

    if not await check_slither_installation():
        raise ValueError("Slither is not installed or not working correctly")

    env = os.environ.copy()
    env["SOLC_ALLOW_PATHS"] = temp_dir

    if remappings:
        env["SLITHER_SOLC_REMAPS"] = ",".join(remappings)

    output_file = os.path.join(temp_dir, "slither_output.json")

    slither_command = [
        "slither",
        temp_dir,
        "--json",
        output_file,
        "--exclude-dependencies",
        "--filter-paths",
        "lib|src/test|src/mock",
        "--exclude",
        "assembly,low-level-calls,naming-convention,solc-version,similar-names",
    ]

    returncode, _, stderr = await run_command(slither_command, temp_dir, env=env)

    if not os.path.exists(output_file):
        logger.error(f"Slither output file not found. Return code: {returncode}")
        # logger.error(f"Stderr: {stderr}")
        raise ValueError(f"Slither analysis failed: {stderr}")

    try:
        with open(output_file, "r", encoding="utf-8") as f:
            slither_output = json.load(f)

        transformed_output = transform_slither_output(slither_output, selected_contracts)
        contract_count = count_unique_contracts(transformed_output)
        if selected_contracts and len(selected_contracts) > 0:
            logger.info(
                f"Slither found issues in {contract_count} out of {len(selected_contracts)} contracts."
            )
        else:
            logger.info(f"Slither found issues in {contract_count} contracts.")

        return transformed_output
    except json.JSONDecodeError as e:
        logger.error(f"Failed to parse Slither output: {e}")
        raise ValueError("Failed to parse Slither output") from e


def count_unique_contracts(slither_output: Dict[str, Any]) -> int:
    contracts_set = set()
    if "findings" in slither_output:
        for finding in slither_output["findings"]:
            if "Contracts" in finding:
                contracts_set.update(finding["Contracts"])
    return len(contracts_set)


async def check_slither_installation():
    try:
        returncode, stdout, stderr = await run_command(["slither", "--version"], ".")
        if returncode == 0:
            logger.info(f"Running Slither version: {stdout.strip()}...")
            return True

        logger.error(f"Slither not found or error checking version: {stderr}")
        return False
    except Exception as e:
        logger.exception(f"Error checking Slither installation: {str(e)}")
        return False
