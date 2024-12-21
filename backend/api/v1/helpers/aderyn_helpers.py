import os
import re
from typing import List

from api.v1.helpers.run_command import run_command
from common import logger
from common.contract_utils import normalize_contract_name
from config.aderyn_detectors_title import ADERYN_DETECTORS_TITLE


async def run_aderyn(temp_dir: str, contracts: List[str]):
    if not await check_aderyn_installation():
        raise ValueError("Aderyn is not installed or not working correctly")

    # It runs aderyn, writes to report.md file
    # Not using --includes parameter because directory structure changes when using Hardhat
    await run_command(["aderyn", temp_dir], cwd=temp_dir)

    # Check if report.md file exists
    report_path = os.path.join(temp_dir, "report.md")
    if not os.path.exists(report_path):
        logger.info("Aderyn report.md file not found")
        return {"findings": [], "total_findings": 0, "severity_counts": {}}

    logger.info("Aderyn generated report.md file")

    with open(report_path, "r") as file:
        report_content = file.read()

    aderyn_finding_list = parse_aderyn_report(report_content, contracts)

    findings_count = len(aderyn_finding_list)
    severity_counts = {
        "High": sum(1 for finding in aderyn_finding_list if finding["Severity"] == "High"),
        "Low": sum(1 for finding in aderyn_finding_list if finding["Severity"] == "Low"),
    }

    return {
        "findings": aderyn_finding_list,
        "total_findings": findings_count,
        "severity_counts": severity_counts,
    }


def parse_aderyn_report(report_content: str, fitler_contracts: List[str]):
    """
    Parses the Aderyn report and returns a list of findings.
    Intuition is get the section(s) that contains the vulnerability and then parse it.
    """
    vulnerability_pattern = (
        r"##\s+([HL]-\d+:.+?)\n\n(.*?)\n\n<details>.*?<summary>.*?</summary>\n\n(.*?)\n\n</details>"
    )

    # Find all vulnerabilities
    vulnerabilities = re.finditer(vulnerability_pattern, report_content, re.DOTALL)

    logger.info("Parsing the vulnerabilities")
    parsed_results = []

    for vuln in vulnerabilities:
        title = vuln.group(1).strip()
        description = vuln.group(2).strip()
        details_section = vuln.group(3).strip()

        # Separate the title into the severity and the issue
        title = title.split(": ")[1]
        severity = title.split(": ")[0]
        # In aderyn some issue title ends with a dot, so we removing it
        title = title.split(".")[0]

        # Replace the title with the title from ADERYN_DETECTORS_TITLE
        try:
            new_title = ADERYN_DETECTORS_TITLE[title]["title"]

        except KeyError:
            logger.info(f"Title not found in ADERYN_DETECTORS_TITLE: {title}")
            continue

        logger.info(f"Title found in ADERYN_DETECTORS_TITLE: {title}")

        severity = "High" if "H-" in severity else "Low"

        # Extract contract names from the details section
        contract_pattern = r"Found in (.*?)\s+\[Line:"
        contracts = re.findall(contract_pattern, details_section)
        code_sections = re.finditer(r"```solidity\n(.*?)\n\s*```", details_section, re.DOTALL)

        contract_code_map = {}
        code_blocks = []

        contracts = [c.strip() for c in contracts]

        for contract, section in zip(contracts, code_sections):
            code = section.group(1).strip()
            contract_code_map[contract] = code
            code_blocks.append(code)

        if not code_blocks:
            logger.info("No code sections found")

        filtered_contracts = [normalize_contract_name(contract) for contract in fitler_contracts]
        contracts = [
            contract
            for contract in contracts
            if normalize_contract_name(contract) in filtered_contracts
        ]

        if not contracts:
            continue

        code_snippets = []
        for contract in contracts:
            if contract in contract_code_map:
                code_snippets.append(
                    f"\nIn contract {contract}:\n```solidity\n{contract_code_map[contract]}\n```"
                )

        description += "\n" + "\n".join(code_snippets)

        logger.info(f"Description: {description}")

        # Create a dictionary for each vulnerability
        vulnerability = {
            "Issue": new_title,
            "Severity": severity,
            "Contracts": contracts,
            "Description": description,
            "Recommendation": "",
        }

        parsed_results.append(vulnerability)

    return parsed_results


async def check_aderyn_installation():
    try:
        returncode, stdout, stderr = await run_command(["aderyn", "--version"], ".")
        if returncode == 0:
            logger.info(f"Running Aderyn version: {stdout.strip()}...")
            return True

        logger.error(f"Aderyn not found or error checking version: {stderr}")
        return False
    except Exception as e:
        logger.exception(f"Error checking Slither installation: {str(e)}")
        return False
