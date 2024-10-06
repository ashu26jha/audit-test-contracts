import json
import os
import re
from typing import Any, Dict, List

from api.v1.utils.forge_helpers import run_command
from common import logger
from common.slither_detectors import SLITHER_DETECTOR_MAP


def extract_contract_from_lines(lines: str) -> str:
    match = re.search(r"src/(.+?)\.sol", lines)
    if match:
        return f"{match.group(1)}.sol"
    return ""


def transform_slither_output(slither_output: Dict[str, Any]) -> Dict[str, Any]:
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
            severity = detector.get("impact", "")
            lines = detector.get("first_markdown_element", "")

            contract = extract_contract_from_lines(lines)
            contracts = [contract] if contract else []

            # Use the SLITHER_DETECTOR_MAP with fallback to original issue
            original_issue = detector.get("check", "")
            mapped_issue = SLITHER_DETECTOR_MAP.get(original_issue, original_issue)

            transformed_result = {
                "Issue": mapped_issue,
                "OriginalIssue": original_issue,  # Keep the original issue for reference
                "Severity": severity,
                "Confidence": detector.get("confidence", ""),
                "Contracts": contracts,
                "Description": detector.get("description", ""),
                "Lines": lines,
            }
            transformed_results.append(transformed_result)

            # Update severity counts
            if severity in severity_counts:
                severity_counts[severity] += 1
            total_findings += 1

    return {
        "findings": transformed_results,
        "total_findings": total_findings,
        "severity_counts": severity_counts,
    }

async def run_slither(
    temp_dir: str
) -> List[Dict[str, Any]]:
    logger.info("Running Slither...")

    if not await check_slither_installation():
        raise ValueError("Slither is not installed or not working correctly")

    src_dir = os.path.join(temp_dir, "src")
    if not os.path.exists(src_dir):
        raise ValueError(f"src directory not found in {temp_dir}")

    # Absolute path for the output file
    output_file = os.path.join(temp_dir, "slither_output.json")

    logger.info(f"Output file: {output_file}")

    slither_command = [
        "slither",
        src_dir,
        "--json",
        output_file,
        "--exclude-dependencies",
        "--filter-paths",
        "lib|src/test|src/mock",
        "--exclude",
        "naming-convention,solc-version,similar-names", # Exclude irrelevant findings
    ]
    returncode, stdout, stderr = await run_command(slither_command, temp_dir)

    # Check if the slither_output.json file exists
    if not os.path.exists(output_file):
        logger.error("Slither output file not found.")
        logger.error(f"Return code: {returncode}")
        logger.error(f"Stdout: {stdout}")
        logger.error(f"Stderr: {stderr}")
        logger.error(f"Contents of temp directory: {os.listdir(temp_dir)}")
        raise ValueError(f"Slither analysis failed: {stderr}")

    # Read and parse the JSON output from Slither
    try:
        with open(output_file, "r") as f:
            slither_output = json.load(f)

        contract_count = len(slither_output.get("contracts", []))
        logger.info(f"Slither analyzed {contract_count} contracts")

        # Transform the Slither output
        transformed_output = transform_slither_output(slither_output)

        return transformed_output
    except json.JSONDecodeError as e:
        logger.error(f"Failed to parse Slither output: {e}")
        # Log the contents of the output file for debugging
        with open(output_file, "r") as f:
            slither_output_content = f.read()
            logger.error(f"Contents of slither_output.json:\n{slither_output_content}")
        raise ValueError("Failed to parse Slither output")


async def check_slither_installation():
    try:
        returncode, stdout, stderr = await run_command(["slither", "--version"], ".")
        if returncode == 0:
            logger.info(f"Slither version: {stdout.strip()}")
            return True
        else:
            logger.error(f"Slither not found or error checking version: {stderr}")
            return False
    except Exception as e:
        logger.error(f"Error checking Slither installation: {str(e)}")
        return False
