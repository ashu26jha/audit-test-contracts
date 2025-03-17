import json
from typing import List, Set

from langfuse.decorators import observe

from api.v1.utilities.critics.helpers.batch_processor import (
    calculate_optimal_batch_size,
    process_findings_in_batches,
)
from api.v1.utilities.critics.schema import IndexedFinding, IndexedFindingList
from config.prompts.duplicate_prompts import DUPLICATE_PROMPT
from config.settings import LLM_UTILITY
from core.llm.send_prompt_to_llm import send_prompt_to_llm_async
from core.models.scan import Finding
from core.utils.errors import CriticError
from core.utils.logger import logger


@observe(name="[CRITICS] deduplicate findings")
async def remove_duplicates_batched(findings: List[Finding]) -> List[Finding]:
    """
    Remove duplicate findings using LLM in a hierarchical batched approach.

    This function handles large lists of findings by:
    1. Splitting findings into configurable batch sizes
    2. Deduplicating each batch independently
    3. Progressively merging and deduplicating pairs of results until a single list remains

    Hierarchical processing is essential for deduplication because:
    - Duplicates may exist across different initial batches
    - All findings must eventually be compared against each other
    - The merge-and-process approach ensures comprehensive comparison

    Args:
        findings: List of findings to deduplicate

    Returns:
        List of deduplicated findings

    Raises:
        CriticError: If deduplication fails, to ensure result quality
        (This is a critical operation that will fail the entire scan if unsuccessful
        to ensure result quality.)
    """
    if not findings:
        return []

    logger.info(f"[DEDUPLICATION] Removing duplicates from {len(findings)} findings...")

    # Calculate batch size based on configuration
    batch_size = calculate_optimal_batch_size(
        items_count=len(findings),
    )

    try:
        # Define the processor function that will be applied to each batch
        async def process_batch(
            indexed_findings_batch: List[IndexedFinding],
        ) -> List[IndexedFinding]:
            try:
                return await remove_duplicates(indexed_findings_batch)
            except CriticError as e:
                # Re-raise CriticError to ensure it's properly handled
                raise e
            except Exception as e:
                # Convert other exceptions to CriticError
                raise CriticError(
                    message=f"Error in deduplication batch: {str(e)}",
                    details={"batch_size": len(indexed_findings_batch)},
                ) from e

        # Process all findings in batches with hierarchical merging
        return await process_findings_in_batches(
            findings=findings,
            processor=process_batch,
            batch_size=batch_size,
            description="findings for deduplication",
            hierarchical=True,  # Deduplication needs hierarchical processing
        )

    except CriticError:
        # Re-raise CriticError to ensure it's properly handled at the scan level
        raise

    except Exception as e:
        error_msg = f"[DEDUPLICATION] Failed to remove duplicates: {str(e)}"
        logger.exception(error_msg)
        raise CriticError(
            message=error_msg,
            details={"original_count": len(findings), "error_type": type(e).__name__},
        ) from e


async def remove_duplicates(indexed_findings: List[IndexedFinding]) -> List[IndexedFinding]:
    """
    Remove duplicate findings from a set of indexed findings using LLM analysis.

    Args:
        indexed_findings: List of indexed findings to deduplicate

    Returns:
        List of deduplicated indexed findings

    Raises:
        CriticError: If deduplication fails or returns invalid results
    """
    try:
        if not indexed_findings:
            return []

        # Get indexes of findings to keep from LLM
        llm_response = await _get_deduplication_indexes(indexed_findings)

        # Validate and filter indexes
        valid_indexes = _validate_deduplication_indexes(llm_response.indexes, indexed_findings)

        # Create a map for efficient lookup
        index_map = {finding.index: finding for finding in indexed_findings}

        # Get deduplicated findings using returned indexes
        deduplicated_findings = [index_map[idx] for idx in valid_indexes]

        logger.info(
            f"[DEDUPLICATION] Batch deduplication: {len(deduplicated_findings)}/{len(indexed_findings)} findings kept"
        )

        return deduplicated_findings

    except CriticError:
        raise

    except Exception as e:
        error_msg = f"[DEDUPLICATION] Failed to remove duplicates: {str(e)}"
        logger.exception(error_msg)
        raise CriticError(
            message=error_msg,
            details={"original_count": len(indexed_findings), "error_type": type(e).__name__},
        ) from e


async def _get_deduplication_indexes(indexed_findings: List[IndexedFinding]) -> IndexedFindingList:
    """
    Get indexes of findings to keep from LLM.

    Args:
        indexed_findings: List of indexed findings to analyze

    Returns:
        LLM response with indexes of findings to keep

    Raises:
        CriticError: If LLM returns no findings
    """
    # Convert indexed findings to dictionaries for the LLM
    findings_dicts = [finding.to_dict() for finding in indexed_findings]

    # Format findings for LLM
    formatted_findings = json.dumps(findings_dicts)
    prompt = DUPLICATE_PROMPT.format(vulnerabilities=formatted_findings)

    # Send the prompt to LLM
    llm_response: IndexedFindingList = await send_prompt_to_llm_async(
        model_type=LLM_UTILITY,
        messages=prompt,
        response_model=IndexedFindingList,
    )

    if not llm_response or not llm_response.indexes:
        logger.warning("[DEDUPLICATION] No findings returned from LLM, returning original findings")
        raise CriticError(
            message="LLM returned no findings during deduplication",
            details={"original_count": len(indexed_findings)},
        )

    return llm_response


def _validate_deduplication_indexes(
    indexes: List[int], indexed_findings: List[IndexedFinding]
) -> Set[int]:
    """
    Validate and filter indexes returned by LLM.

    Args:
        indexes: List of indexes returned by LLM
        indexed_findings: List of indexed findings

    Returns:
        Set of valid indexes

    Raises:
        CriticError: If no valid indexes are found
    """
    # Create a set of valid indexes for O(1) lookup
    valid_index_set = {finding.index for finding in indexed_findings}

    # Filter out invalid indexes
    valid_indexes = [idx for idx in indexes if idx in valid_index_set]

    if len(valid_indexes) != len(indexes):
        logger.warning(
            f"[DEDUPLICATION] LLM returned {len(indexes) - len(valid_indexes)} invalid indexes - filtering them out"
        )

    if not valid_indexes:
        raise CriticError(
            message="No valid indexes returned during deduplication",
            details={
                "original_count": len(indexed_findings),
                "returned_indexes": indexes,
            },
        )

    return set(valid_indexes)  # Convert to set for faster lookups
