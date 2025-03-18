import json
from typing import Dict, List

from langfuse.decorators import observe

from api.v1.utilities.critics.helpers.batch_processor import (
    _process_in_batches,
    calculate_optimal_batch_size,
)
from api.v1.utilities.critics.helpers.contract_grouping import process_findings_by_contract_groups
from api.v1.utilities.critics.schema import EnrichedFindingList, IndexedFinding
from config.prompts.enrichment_prompts import FINDING_ENRICHMENT_PROMPT
from config.settings import LLM_UTILITY, MAX_BATCHES, MIN_BATCH_SIZE
from core.llm.send_prompt_to_llm import send_prompt_to_llm_async
from core.models.scan import Finding
from core.utils.logger import logger
from core.utils.severity import Severity

# Maximum number of findings to process in a single batch
MAX_FINDINGS_PER_BATCH = 15


@observe(name="[CRITICS] enrich findings")
async def enrich_findings_batched(
    findings: List[Finding], contract_contents: Dict[str, str]
) -> List[Finding]:
    """
    Enrich findings by appending concise insight summaries based on
    the information collected during mitigation and validation phases.

    This process:
    1. Groups findings by their primary contract
    2. For each group, generates insight summaries based on mitigation analysis,
      counter-arguments, and justifications
    3. Appends these summaries to the original findings
    4. Optionally updates severity ratings based on comprehensive analysis

    Args:
        findings: List of findings to enrich
        contract_contents: Dictionary mapping contract filenames to their source code

    Returns:
        List of findings with appended insight summaries
    """
    if not findings:
        return []

    logger.info(f"[ENRICHMENT] Generating insight summaries for {len(findings)} findings...")

    try:
        # Process findings by contract groups
        return await process_findings_by_contract_groups(
            findings=findings,
            contract_contents=contract_contents,
            processor=enrich_findings_group,
            operation_name="enrichment",
        )
    except Exception as e:
        logger.error(f"[ENRICHMENT] Error during findings enrichment: {e}")
        logger.info("[ENRICHMENT] Falling back to original findings without enrichment")
        return findings


async def enrich_findings_group(
    indexed_findings: List[IndexedFinding], contract_code: str
) -> List[IndexedFinding]:
    """
    Generate insight summaries for a group of findings and append them to the original descriptions.

    Args:
        indexed_findings: List of indexed findings to enhance
        contract_code: The relevant contract code for these findings

    Returns:
        List of indexed findings with appended insight summaries
    """
    try:
        if not indexed_findings:
            return []

        # Check if we need to batch process due to large number of findings
        if len(indexed_findings) > MAX_FINDINGS_PER_BATCH:
            return await _batch_process_enrichment(indexed_findings, contract_code)

        # For smaller groups, process all findings together
        return await _execute_enrichment(indexed_findings, contract_code)

    except Exception as e:
        error_msg = f"[ENRICHMENT] Failed to enrich findings: {str(e)}"
        logger.exception(error_msg)
        # Return original findings on error
        return indexed_findings


async def _batch_process_enrichment(
    indexed_findings: List[IndexedFinding], contract_code: str
) -> List[IndexedFinding]:
    """
    Process a large group of findings in smaller batches for enrichment.

    Args:
        indexed_findings: List of indexed findings to enhance
        contract_code: The relevant contract code for these findings

    Returns:
        List of indexed findings with appended insight summaries
    """
    total_findings = len(indexed_findings)
    logger.info(
        f"[ENRICHMENT] Large group detected with {total_findings} findings. Using batch processing."
    )

    # Calculate optimal batch size
    batch_size = calculate_optimal_batch_size(
        items_count=total_findings,
        min_batch_size=MIN_BATCH_SIZE,
        max_batches=MAX_BATCHES,
    )

    # Cap batch size
    batch_size = min(batch_size, MAX_FINDINGS_PER_BATCH)

    # Process batches
    async def process_batch(batch):
        return await _execute_enrichment(batch, contract_code)

    return await _process_in_batches(
        items=indexed_findings,
        processor=process_batch,
        batch_size=batch_size,
        description="findings for enrichment",
        hierarchical=False,
    )


async def _execute_enrichment(
    indexed_findings: List[IndexedFinding], contract_code: str
) -> List[IndexedFinding]:
    """
    Use LLM to generate concise summaries of insights from critic information.

    This function:
    1. Extracts information from mitigation, counter-arguments, and justifications
    2. Uses LLM to create concise summaries and potentially update severity
    3. Appends the summaries to the original finding descriptions

    Args:
        indexed_findings: List of indexed findings to enhance
        contract_code: The relevant contract code for these findings

    Returns:
        List of indexed findings with appended insight summaries
    """
    # Convert indexed findings to dictionaries for the LLM
    findings_dicts = []

    for indexed_finding in indexed_findings:
        finding_dict = indexed_finding.to_dict()

        # Add critic information to the dictionary
        if hasattr(indexed_finding.finding, "Mitigation") and indexed_finding.finding.Mitigation:
            finding_dict["mitigation"] = indexed_finding.finding.Mitigation

        if (
            hasattr(indexed_finding.finding, "CounterArguments")
            and indexed_finding.finding.CounterArguments
        ):
            finding_dict["counter_arguments"] = indexed_finding.finding.CounterArguments

        if (
            hasattr(indexed_finding.finding, "Justification")
            and indexed_finding.finding.Justification
        ):
            finding_dict["justification"] = indexed_finding.finding.Justification

        findings_dicts.append(finding_dict)

    # Skip LLM call if no findings have critic information
    if not any(
        "mitigation" in f or "counter_arguments" in f or "justification" in f
        for f in findings_dicts
    ):
        logger.info("[ENRICHMENT] No critic information found in findings, skipping enrichment")
        return indexed_findings

    # Format findings for LLM
    formatted_findings = json.dumps(findings_dicts)
    prompt = FINDING_ENRICHMENT_PROMPT.format(
        findings=formatted_findings, contract_code=contract_code
    )

    # Send to LLM
    enrichment_response = await send_prompt_to_llm_async(
        model_type=LLM_UTILITY,
        messages=prompt,
        response_model=EnrichedFindingList,
    )

    if not enrichment_response or not enrichment_response.enriched_findings:
        logger.warning("[ENRICHMENT] No enriched findings returned, keeping original findings")
        return indexed_findings

    # Create a map of index to enriched finding for efficient lookup
    enrichment_map = {ef.index: ef for ef in enrichment_response.enriched_findings}

    # Apply updates to findings
    severity_updates_count = 0
    insight_summaries_count = 0

    for indexed_finding in indexed_findings:
        index = indexed_finding.index
        if index in enrichment_map:
            enriched = enrichment_map[index]

            # Append insight summary to the original description
            if enriched.insight_summary:
                insight_summaries_count += 1
                indexed_finding.finding.Description += (
                    f"\n\nAdditional Insights: {enriched.insight_summary}"
                )

            # Update severity if provided and different from the original
            if enriched.updated_severity:
                # Convert string severity to Severity enum
                severity_enum = Severity.validate(enriched.updated_severity)

                # Only count as update if severity is actually different
                if severity_enum != indexed_finding.finding.Severity:
                    severity_updates_count += 1
                    indexed_finding.finding.Severity = severity_enum

    logger.info(
        f"[ENRICHMENT] Added insight summaries to {insight_summaries_count} findings and updated severities for {severity_updates_count} findings"
    )
    return indexed_findings
