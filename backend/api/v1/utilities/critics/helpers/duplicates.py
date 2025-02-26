import json
from typing import List

from langfuse.decorators import observe

from api.v1.utilities.critics.schema import IndexedFindingList
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

        # Add index to each finding
        indexed_findings = []
        for idx, finding in enumerate(findings):
            finding_dict = finding.model_dump()
            finding_dict["index"] = idx
            indexed_findings.append(finding_dict)

        # Format findings for LLM
        formatted_findings = json.dumps(indexed_findings)
        prompt = DUPLICATE_PROMPT.format(vulnerabilities=formatted_findings)

        # Send the prompt to LLM
        llm_response: IndexedFindingList = await send_prompt_to_llm_async(
            model_type=LLM_UTILITY,
            messages=prompt,
            response_model=IndexedFindingList,
        )

        if not llm_response or not llm_response.indexes:
            logger.warning("[Critics] No findings returned from LLM, returning original findings")
            raise CriticError(
                message="LLM returned no findings during deduplication",
                details={"original_count": len(findings)},
            )

        # Validate indexes are within bounds
        max_index = len(findings) - 1
        valid_indexes = [idx for idx in llm_response.indexes if 0 <= idx <= max_index]

        if len(valid_indexes) != len(llm_response.indexes):
            logger.warning(
                f"[Critics] LLM returned {len(llm_response.indexes) - len(valid_indexes)} invalid indexes - filtering them out"
            )

        if not valid_indexes:
            raise CriticError(
                message="No valid indexes returned during deduplication",
                details={
                    "original_count": len(findings),
                    "returned_indexes": llm_response.indexes,
                },
            )

        # Get deduplicated findings using returned indexes
        deduplicated_findings = [findings[idx] for idx in valid_indexes]

        logger.info(
            f"[Critics] Total findings after duplicate removal: {len(deduplicated_findings)} (from {len(findings)})"
        )

        return deduplicated_findings

    except CriticError:
        raise

    except Exception as e:
        error_msg = f"[Critics] Failed to remove duplicates: {str(e)}"
        logger.exception(error_msg)
        raise CriticError(
            message=error_msg,
            details={"original_count": len(findings), "error_type": type(e).__name__},
        ) from e
