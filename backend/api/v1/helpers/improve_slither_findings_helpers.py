import asyncio
from typing import Dict, List

from api.v1.schemas.context_scan_schema import FindingList
from api.v1.schemas.static_analyzer_schema import TransformedSlitherResult
from common.logger import logger
from common.parse_llm_response import parse_model_response
from common.send_prompt_to_llm import send_prompt_to_llm_async
from common.severity import Severity
from config.prompts.improve_slither_prompts import IMPROVE_SLITHER_PROMPT
from config.settings import DELAY, LLM_MODEL_BEST_2, MAX_RETRIES

# Mapping from our severity to Slither's severity
SEVERITY_TO_SLITHER = {
    Severity.HIGH: "High",
    Severity.MEDIUM: "Medium",
    Severity.LOW: "Low",
    Severity.INFO: "Informational",
    Severity.BEST_PRACTICES: "Optimization",
}


async def improve_slither_findings(vulns: List[Dict]) -> List[Dict]:
    """
    Sends the slither findings to the LLM for improvement and returns the improved findings.

    Args:
        vulns (List[Dict]): list of vulnerabilities found by Slither.

    Returns:
        List[Dict]: A list of improved vulnerabilities.
    """
    # Prepare the prompt
    prompt = IMPROVE_SLITHER_PROMPT.format(vulnerabilities=vulns)

    for attempt in range(1, MAX_RETRIES + 1):
        try:
            # Send the prompt to the LLM
            llm_response = await send_prompt_to_llm_async(LLM_MODEL_BEST_2, prompt)

            # Use parse_model_response to handle the LLM response
            parsed_response = parse_model_response(llm_response, FindingList)

            if not isinstance(parsed_response, FindingList):
                logger.error(f"Parsed response is not a FindingList: {parsed_response}")
                raise ValueError("Parsed response is not a FindingList")

            # Convert Finding objects to TransformedSlitherResult objects
            improved_findings = []
            for i, finding in enumerate(parsed_response.findings):
                try:
                    original_vuln = vulns[i] if i < len(vulns) else {}
                    # Convert our severity to Slither's severity
                    severity_enum = Severity.from_str(finding.Severity)
                    slither_severity = SEVERITY_TO_SLITHER[severity_enum]

                    improved_finding = TransformedSlitherResult(
                        Issue=finding.Issue,
                        OriginalIssue=original_vuln.get("OriginalIssue", ""),
                        Severity=slither_severity,
                        Confidence=original_vuln.get("Confidence", "High"),
                        Contracts=finding.Contracts,
                        Description=finding.Description,
                        Lines=original_vuln.get("Lines", ""),
                    )
                    improved_findings.append(improved_finding.model_dump())
                except Exception as e:
                    logger.error(f"Error transforming finding: {e}")
                    logger.error(f"Problematic finding: {finding}")
                    logger.error(f"Original vulnerability: {original_vuln}")
                    continue

            return improved_findings

        except Exception as e:
            logger.error(f"Attempt {attempt} failed: {str(e)}")
            logger.error(f"LLM response: {llm_response}")

            if attempt < MAX_RETRIES:
                logger.info(f"Retrying in {DELAY} seconds...")
                await asyncio.sleep(DELAY)
            else:
                logger.warning("Max retries reached. Returning original vulnerabilities")
                return vulns

    return vulns
