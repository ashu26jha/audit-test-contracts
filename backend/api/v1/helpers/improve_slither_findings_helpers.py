import asyncio
from typing import List

from api.v1.schemas.context_scan_schema import Finding, FindingList
from api.v1.schemas.static_analyzer_schema import TransformedSlitherResult
from common.logger import logger
from common.send_prompt_to_llm import send_prompt_to_llm_async
from common.severity import Severity
from config.prompts.improve_slither_prompts import IMPROVE_SLITHER_PROMPT
from config.settings import DELAY, LLM_MODEL_BEST_3, MAX_RETRIES

# Mapping from our severity to Slither's severity
SEVERITY_TO_SLITHER = {
    Severity.HIGH: "High",
    Severity.MEDIUM: "Medium",
    Severity.LOW: "Low",
    Severity.INFO: "Informational",
    Severity.BEST_PRACTICES: "Optimization",
}


async def improve_slither_findings(vulns: List[Finding]) -> List[Finding]:
    """
    Sends the slither and aderyn findings to the LLM for improvement and returns the improved findings.

    Args:
        vulns (List[Dict]): list of vulnerabilities found by Slither.

    Returns:
        List[Dict]: A list of improved vulnerabilities.
    """
    prompt = IMPROVE_SLITHER_PROMPT.format(vulnerabilities=vulns)

    for attempt in range(1, MAX_RETRIES + 1):
        try:
            improved_findings = await process_llm_response(vulns, prompt)
            return improved_findings

        except Exception as e:
            if not should_retry(attempt, e):
                return vulns
            await asyncio.sleep(DELAY)

    return vulns


async def process_llm_response(vulns: List[Finding], prompt: str) -> List[Finding]:
    """Helper function to process LLM response and transform findings."""
    llm_response = await send_prompt_to_llm_async(
        LLM_MODEL_BEST_3, prompt, response_model=FindingList
    )

    if not isinstance(llm_response, FindingList):
        raise ValueError("LLM response is not a FindingList")

    return transform_findings(vulns, llm_response.findings)


def transform_findings(original_vulns: List[Finding], llm_findings: List[Finding]) -> List[Finding]:
    """Helper function to transform findings with error handling."""
    improved_findings = []

    for i, finding in enumerate(llm_findings):
        try:
            original_vuln = original_vulns[i] if i < len(original_vulns) else {}
            improved_finding = create_transformed_finding(finding, original_vuln)
            improved_findings.append(improved_finding.model_dump())
        except Exception as e:
            logger.error(f"Error transforming finding: {e}")
            logger.error(f"Problematic finding: {finding}")
            logger.error(f"Original vulnerability: {original_vuln}")
            continue

    return improved_findings


def create_transformed_finding(finding: Finding, original_vuln: dict) -> TransformedSlitherResult:
    """Helper function to create a transformed finding."""
    severity_enum = Severity.from_str(finding.Severity)
    slither_severity = SEVERITY_TO_SLITHER[severity_enum]

    return TransformedSlitherResult(
        Issue=finding.Issue,
        OriginalIssue=original_vuln.get("OriginalIssue", ""),
        Severity=slither_severity,
        Confidence=original_vuln.get("Confidence", "High"),
        Contracts=finding.Contracts,
        Description=finding.Description,
        Lines=original_vuln.get("Lines", ""),
    )


def should_retry(attempt: int, error: Exception) -> bool:
    """Helper function to determine if retry is needed."""
    logger.error(f"Attempt {attempt} failed: {str(error)}")
    if attempt < MAX_RETRIES:
        logger.info(f"Retrying in {DELAY} seconds...")
        return True
    logger.warning("Max retries reached. Returning original vulnerabilities")
    return False
