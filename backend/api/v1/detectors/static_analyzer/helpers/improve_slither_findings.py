from typing import List

from langfuse.decorators import observe

from api.v1.detectors.context_scan.schema import FindingList
from api.v1.detectors.static_analyzer.schema import TransformedSlitherResult
from config.prompts.improve_slither_prompts import IMPROVE_SLITHER_PROMPT
from config.settings import LLM_UTILITY
from core.llm.send_prompt_to_llm import send_prompt_to_llm_async
from core.models.scan import Finding
from core.utils.logger import logger
from core.utils.retry_helper import retry_async_operation
from core.utils.severity import Severity


@observe(name="improve_slither_findings")
async def improve_slither_findings(findings: List[Finding]) -> List[TransformedSlitherResult]:
    """
    Improve the descriptions of the findings using LLM.

    Args:
        findings: List of Finding objects to improve (from both Slither and Aderyn)

    Returns:
        List of improved findings as TransformedSlitherResult objects
    """
    if not findings:
        logger.info("No findings to improve")
        return []

    logger.info(f"[Improve Findings] Improving descriptions for {len(findings)} findings...")

    # Process all findings with LLM
    llm_findings = await process_llm_response(findings)

    # Transform the findings
    improved_findings = transform_findings(findings, llm_findings)

    logger.info(
        f"[Improve Findings] Successfully improved descriptions for {len(improved_findings)} findings"
    )
    return improved_findings


async def process_llm_response(vulns: List[Finding]) -> List[Finding]:
    """
    Process the vulnerabilities using LLM to get improved descriptions.

    Args:
        vulns: List of Finding objects to improve (from both Slither and Aderyn)

    Returns:
        List of findings with improved descriptions from the LLM
    """
    # Format the vulnerabilities for the prompt
    formatted_vulns = []
    for vuln in vulns:
        # Create a formatted representation of the vulnerability
        formatted_vuln = {
            "Issue": vuln.Issue,
            "Severity": vuln.Severity.value if hasattr(vuln.Severity, "value") else vuln.Severity,
            "Contracts": vuln.Contracts,
            "Description": vuln.Description,
        }
        formatted_vulns.append(formatted_vuln)

    prompt = IMPROVE_SLITHER_PROMPT.format(vulnerabilities=formatted_vulns)

    try:
        # Use the retry helper to handle retries
        llm_response = await retry_async_operation(
            send_prompt_to_llm_async,
            model_type=LLM_UTILITY,
            messages=prompt,
            response_model=FindingList,
        )

        if not isinstance(llm_response, FindingList):
            raise ValueError("LLM response is not a FindingList")

        logger.info(
            f"[Improve Findings] Received {len(llm_response.findings)} improved findings from LLM"
        )
        return llm_response.findings
    except Exception as e:
        logger.error(f"[Improve Findings] Failed to improve findings after retries: {e}")
        return vulns


def transform_findings(
    original_vulns: List[Finding], llm_findings: List[Finding]
) -> List[TransformedSlitherResult]:
    """
    Helper function to transform findings with error handling.

    Args:
        original_vulns: List of original Finding objects (from both Slither and Aderyn)
        llm_findings: List of findings from LLM with improved descriptions

    Returns:
        List of transformed findings as TransformedSlitherResult objects
    """
    improved_findings = []

    for i, finding in enumerate(llm_findings):
        try:
            # Get the original vulnerability if available, otherwise use an empty dict
            original_vuln = original_vulns[i] if i < len(original_vulns) else None

            if original_vuln is None:
                logger.warning(
                    f"[Improve Findings] No original vulnerability found for finding {i}"
                )
                continue

            improved_finding = create_transformed_finding(finding, original_vuln)
            improved_findings.append(improved_finding)
        except Exception as e:
            logger.error(f"[Improve Findings] Error transforming finding {i}: {e}")
            logger.error(f"[Improve Findings] Problematic finding: {finding}")
            logger.error(f"[Improve Findings] Original vulnerability: {original_vuln}")
            continue

    logger.info(f"[Improve Findings] Successfully transformed {len(improved_findings)} findings")
    return improved_findings


def create_transformed_finding(
    finding: Finding, original_vuln: Finding
) -> TransformedSlitherResult:
    """
    Helper function to create a transformed finding.

    Args:
        finding: The finding from LLM with improved description
        original_vuln: The original Finding object

    Returns:
        A TransformedSlitherResult object
    """
    severity_enum = (
        finding.Severity
        if isinstance(finding.Severity, Severity)
        else Severity.from_str(finding.Severity)
    )

    # Extract the original issue from the finding
    original_issue = getattr(original_vuln, "Issue", "")

    return TransformedSlitherResult(
        Issue=finding.Issue,
        OriginalIssue=original_issue,
        Severity=severity_enum,
        Confidence=getattr(original_vuln, "Confidence", "High"),
        Contracts=finding.Contracts,
        Description=finding.Description,
        Lines=getattr(original_vuln, "Lines", ""),
    )
