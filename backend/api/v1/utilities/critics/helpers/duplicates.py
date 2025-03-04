import json
from typing import List

from langfuse.decorators import observe

from api.v1.utilities.critics.schema import IndexedFindingList
from config.prompts.duplicate_prompts import DUPLICATE_PROMPT
from config.settings import DEDUP_MAX_BATCHES, DEDUP_MIN_BATCH_SIZE, LLM_UTILITY
from core.llm.send_prompt_to_llm import send_prompt_to_llm_async
from core.models.scan import Finding
from core.utils.errors import CriticError
from core.utils.logger import logger


@observe(name="remove_duplicates_batched")
async def remove_duplicates_batched(findings: List[Finding]) -> List[Finding]:
    """
    Remove duplicate findings using LLM in a hierarchical batched approach.

    This function handles large lists of findings by:
    1. Splitting findings into configurable batch sizes
    2. Deduplicating each batch independently
    3. Progressively merging and deduplicating pairs of results until a single list remains

    Args:
        findings: List of findings to deduplicate

    Returns:
        List of deduplicated findings

    Note:
        This is a critical operation that will fail the entire scan if unsuccessful
        to ensure result quality.
    """

    if not findings:
        return []

    logger.info(f"[Critics] Removing duplicates from {len(findings)} findings...")

    # Calculate the number of batches using configurable settings
    min_batch_size = DEDUP_MIN_BATCH_SIZE
    num_batches = min(DEDUP_MAX_BATCHES, (len(findings) + min_batch_size - 1) // min_batch_size)
    batch_size = (len(findings) + num_batches - 1) // num_batches

    # Split findings into batches
    groups = [findings[i : i + batch_size] for i in range(0, len(findings), batch_size)]

    logger.info(
        f"[Critics] Configured {len(groups)} batches with batch size ~{batch_size} for {len(findings)} findings"
    )

    # First level - process initial groups
    first_level_results = []
    for group in groups:
        deduped_group = await remove_duplicates(group)
        first_level_results.append(deduped_group)

    # Keep merging pairs until we have one final list
    current_level = first_level_results
    while len(current_level) > 1:
        next_level = []
        # Process pairs
        for i in range(0, len(current_level), 2):
            if i + 1 < len(current_level):
                # Merge pair and deduplicate
                merged = current_level[i] + current_level[i + 1]
                deduped = await remove_duplicates(merged)
                next_level.append(deduped)
            else:
                # Odd one out - pass through
                next_level.append(current_level[i])
        current_level = next_level

    logger.info(
        f"[Critics] Total findings after duplicate removal: {len(current_level[0])} (from {len(findings)})"
    )

    return current_level[0] if current_level else []


@observe(name="remove_duplicates")
async def remove_duplicates(findings: List[Finding]) -> List[Finding]:
    """
    Remove duplicate findings from a list of findings using LLM analysis.

    This function:
    1. Indexes each finding with a unique identifier
    2. Sends the findings to an LLM with a specialized prompt
    3. Processes the LLM response to extract the deduplicated findings

    Args:
        findings: List of findings to deduplicate

    Returns:
        List of deduplicated findings

    Raises:
        CriticError: If deduplication fails or returns invalid results. This will fail the entire
            scan process as duplicate removal is essential for result quality.
    """

    try:
        if not findings:
            return []

        # Add index to each finding
        indexed_findings = []
        for idx, finding in enumerate(findings):
            finding_dict = finding.model_dump(mode="json")
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
