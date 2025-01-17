import asyncio
from typing import List

from langfuse.decorators import observe

from api.v1.detectors.context_scan.schema import FindingList
from api.v1.detectors.static_analyzer.schema import TransformedSlitherResult
from config.prompts.improve_slither_prompts import IMPROVE_SLITHER_PROMPT
from config.settings import DELAY, LLM_UTILITY, MAX_RETRIES
from core.llm.send_prompt_to_llm import send_prompt_to_llm_async
from core.models.scan import Finding
from core.utils.logger import logger
from core.utils.severity import Severity

# Mapping from our severity to Slither's severity
SEVERITY_TO_SLITHER = {
    Severity.HIGH: "High",
    Severity.MEDIUM: "Medium",
    Severity.LOW: "Low",
    Severity.INFO: "Informational",
    Severity.BEST_PRACTICES: "Optimization",
}


@observe(name="improve_slither_findings")
async def improve_slither_findings(
    findings: List[TransformedSlitherResult],
) -> List[TransformedSlitherResult]:
    """
    Sends the findings to the LLM for improvement and returns the improved findings.

    Args:
        findings (List[TransformedSlitherResult]): list of findings to improve.

    Returns:
        List[TransformedSlitherResult]: A list of improved findings.
    """
    logger.info(f"[Improve Findings] Improving descriptions for {len(findings)} findings...")

    prompt = IMPROVE_SLITHER_PROMPT.format(vulnerabilities=findings)

    for attempt in range(1, MAX_RETRIES + 1):
        try:
            improved_findings = await process_llm_response(findings, prompt)
            return improved_findings

        except Exception as e:
            if not should_retry(attempt, e):
                return findings
            await asyncio.sleep(DELAY)

    logger.info(
        f"[Improve Findings] Successfully improved descriptions for {len(findings)} findings"
    )
    return findings


async def process_llm_response(vulns: List[Finding], prompt: str) -> List[Finding]:
    """Process the LLM response and create improved findings."""

    llm_response = await send_prompt_to_llm_async(
        model_type=LLM_UTILITY, messages=prompt, response_model=FindingList
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
    logger.warning("Max retries reached. Returning original findings")
    return False
