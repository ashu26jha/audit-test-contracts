import json
from typing import List

from langfuse.decorators import observe

from api.v1.detectors.context_scan.schema import FindingList
from config.prompts.duplicate_prompts import DUPLICATE_PROMPT
from config.settings import LLM_UTILITY
from core.llm.send_prompt_to_llm import send_prompt_to_llm_async
from core.models.scan import Finding
from core.utils.errors import CriticError
from core.utils.logger import logger


@observe(name="remove_duplicates")
async def remove_duplicates_async(findings: List[Finding]) -> List[Finding]:
    """
    Remove duplicate findings using LLM. This is a critical operation that will fail
    the entire scan if unsuccessful to ensure result quality.

    Args:
        findings: List of findings to deduplicate

    Returns:
        List of deduplicated findings

    Raises:
        CriticError: If deduplication fails or returns invalid results. This will fail the entire
            scan process as duplicate removal is essential for result quality.
    """
    logger.info(f"[Critics] Removing duplicates from {len(findings)} findings...")

    try:
        if not findings:
            return []

        # Format findings for LLM
        formatted_findings = json.dumps([finding.model_dump() for finding in findings])
        prompt = DUPLICATE_PROMPT.format(vulnerabilities=formatted_findings)

        # Send the prompt to LLM
        llm_response: FindingList = await send_prompt_to_llm_async(
            model_type=LLM_UTILITY,
            messages=prompt,
            response_model=FindingList,
        )

        if not llm_response or not llm_response.findings:
            logger.warning("[Critics] No findings returned from LLM, returning original findings")
            raise CriticError(
                message="LLM returned no findings during deduplication",
                details={"original_count": len(findings)},
            )

        logger.info(
            f"[Critics] Total findings after duplicate removal: {len(llm_response.findings)}"
        )
        return llm_response.findings

    except CriticError:
        raise

    except Exception as e:
        error_msg = f"[Critics] Failed to remove duplicates: {str(e)}"
        logger.exception(error_msg)
        raise CriticError(
            message=error_msg,
            details={"original_count": len(findings), "error_type": type(e).__name__},
        ) from e
