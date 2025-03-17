import math
from typing import Awaitable, Callable, List, TypeVar

from langfuse.decorators import observe

from api.v1.utilities.critics.schema import IndexedFinding
from config.settings import MAX_BATCHES, MIN_BATCH_SIZE
from core.models.scan import Finding
from core.utils.logger import logger

# For contract-based processing, see contract_grouping.py which provides
# functions to group findings by their primary contract and process them accordingly.

T = TypeVar("T")
R = TypeVar("R")


@observe(name="process_findings_in_batches")
async def process_findings_in_batches(
    findings: List[Finding],
    processor: Callable[[List[IndexedFinding]], Awaitable[List[IndexedFinding]]],
    batch_size: int,
    description: str = "findings",
    hierarchical: bool = False,
) -> List[Finding]:
    """
    Process a list of findings in batches, handling the conversion to and from IndexedFinding.

    Args:
        findings: List of Finding objects to process
        processor: Async function that processes a batch of IndexedFinding objects
        batch_size: Size of each batch
        description: Description of the findings for logging
        hierarchical: If True, uses hierarchical processing

    Returns:
        List of processed Finding objects
    """
    # Convert findings to IndexedFinding objects
    indexed_findings = _index_findings(findings)

    # Process in batches
    processed_indexed_findings = await _process_in_batches(
        items=indexed_findings,
        processor=processor,
        batch_size=batch_size,
        description=description,
        hierarchical=hierarchical,
    )

    # Convert back to Finding objects
    return _unindex_findings(processed_indexed_findings)


def calculate_optimal_batch_size(
    items_count: int,
    min_batch_size: int = MIN_BATCH_SIZE,
    max_batches: int = MAX_BATCHES,
) -> int:
    """
    Calculate the optimal batch size based on configuration settings.

    This function balances the need for efficient processing (fewer batches)
    with the constraints of LLM context windows (smaller batch sizes).

    The calculation ensures:
    1. Each batch has at least min_batch_size items (unless there are fewer items total)
    2. The number of batches doesn't exceed max_batches
    3. Items are distributed as evenly as possible across batches

    Args:
        items_count: Number of items to process
        operation_name: Name of the operation for logging
        min_batch_size: Minimum size of each batch (defaults to global MIN_BATCH_SIZE)
        max_batches: Maximum number of batches to create (defaults to global MAX_BATCHES)

    Returns:
        Optimal batch size
    """
    if items_count == 0:
        return min_batch_size

    # Calculate number of batches (capped at max_batches)
    num_batches = min(max_batches, (items_count + min_batch_size - 1) // min_batch_size)

    # Calculate batch size based on number of batches
    return (items_count + num_batches - 1) // num_batches


async def _process_in_batches(
    items: List[T],
    processor: Callable[[List[T]], Awaitable[List[R]]],
    batch_size: int,
    description: str = "items",
    hierarchical: bool = False,
) -> List[R]:
    """
    Process a list of items in batches using the provided processor function.

    Args:
        items: List of items to process
        processor: Async function that processes a batch of items
        batch_size: Size of each batch
        description: Description of the items for logging
        hierarchical: If True, uses hierarchical processing (pairs of results are merged and reprocessed)
                     This is necessary for operations like deduplication where items need to be compared
                     against each other across batches. For operations that process each item independently
                     (like mitigation and validation), hierarchical processing is not needed.

    Returns:
        List of processed items
    """
    if not items:
        return []

    # Calculate optimal number of batches
    num_batches = math.ceil(len(items) / batch_size)

    logger.info(
        f"[BatchProcessor] Processing {len(items)} {description} in {num_batches} batches (size: {batch_size})"
    )

    # Split items into batches
    batches = [items[i : i + batch_size] for i in range(0, len(items), batch_size)]

    # First level - process initial batches
    first_level_results = []
    for i, batch in enumerate(batches):
        logger.info(
            f"[BatchProcessor] Processing batch {i + 1}/{len(batches)} with {len(batch)} {description}"
        )
        processed_batch = await processor(batch)
        first_level_results.append(processed_batch)

    # If not hierarchical, just flatten the results
    if not hierarchical:
        flattened_results = []
        for batch_result in first_level_results:
            flattened_results.extend(batch_result)
        logger.info(
            f"[BatchProcessor] Completed processing {len(items)} {description}, returned {len(flattened_results)} results"
        )
        return flattened_results

    # For hierarchical processing, keep merging pairs until we have one final list
    current_level = first_level_results
    level = 1

    while len(current_level) > 1:
        next_level = []
        logger.info(
            f"[BatchProcessor] Hierarchical level {level}: processing {len(current_level)} result groups"
        )

        # Process pairs
        for i in range(0, len(current_level), 2):
            if i + 1 < len(current_level):
                # Merge pair and process
                merged = current_level[i] + current_level[i + 1]
                processed = await processor(merged)
                next_level.append(processed)
            else:
                # Odd one out - pass through
                next_level.append(current_level[i])

        current_level = next_level
        level += 1

    final_results = current_level[0] if current_level else []
    logger.info(
        f"[BatchProcessor] Completed hierarchical processing of {len(items)} {description}, returned {len(final_results)} results"
    )

    return final_results


def _index_findings(findings: List[Finding]) -> List[IndexedFinding]:
    """
    Convert a list of Finding objects to IndexedFinding objects.

    Args:
        findings: List of Finding objects

    Returns:
        List of IndexedFinding objects with sequential indexes
    """
    return [IndexedFinding(index=i, finding=finding) for i, finding in enumerate(findings)]


def _unindex_findings(indexed_findings: List[IndexedFinding]) -> List[Finding]:
    """
    Convert a list of IndexedFinding objects back to Finding objects.

    Args:
        indexed_findings: List of IndexedFinding objects

    Returns:
        List of Finding objects
    """
    return [indexed_finding.finding for indexed_finding in indexed_findings]
