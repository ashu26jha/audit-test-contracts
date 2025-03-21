import json
from typing import Dict, List

from langfuse.decorators import observe

from api.v1.utilities.critics.helpers.contract_grouping import process_findings_by_contract_groups
from api.v1.utilities.critics.schema import IndexedFinding, MitigationUpdate, MitigationUpdateList
from config.prompts.mitigation_prompts import MITIGATION_PROMPT
from config.settings import LLM_UTILITY
from core.llm.send_prompt_to_llm import send_prompt_to_llm_async
from core.models.scan import Finding
from core.utils.logger import logger
from core.utils.severity import Severity


@observe(name="[CRITICS] mitigate findings")
async def mitigate_findings_async(
    findings: List[Finding],
    contract_contents: Dict[str, str],
) -> List[Finding]:
    """
    Process findings through mitigation analysis to adjust severity ratings,
    add additional context, and optionally remove false positives.

    This function uses contract-based grouping to process findings more effectively,
    ensuring that each finding is analyzed in the context of its relevant contracts.

    Mitigation may:
    1. Adjust severity ratings up or down
    2. Add explanatory comments to findings
    3. Remove findings identified as false positives

    Args:
        findings: List of findings to analyze
        contract_contents: Dictionary mapping contract filenames to their source code

    Returns:
        List[Finding]: Findings with potentially adjusted severities,
        with false positives removed, or original findings if validation fails
    """
    logger.info(f"[MITIGATION] Starting mitigation analysis for {len(findings)} findings...")

    if not findings:
        return []

    try:
        # Process findings by contract groups
        return await process_findings_by_contract_groups(
            findings=findings,
            contract_contents=contract_contents,
            processor=mitigate_findings,
            operation_name="mitigation",
        )

    except Exception as e:
        logger.error(f"[MITIGATION] Error during findings mitigation: {e}")
        logger.info("[MITIGATION] Falling back to original findings without mitigation")
        return findings


async def mitigate_findings(
    indexed_findings: List[IndexedFinding],
    contract_code: str,
) -> List[IndexedFinding]:
    """
    Process the given findings through mitigation analysis.

    Args:
        indexed_findings: List of indexed findings to analyze
        contract_code: The relevant contract code for these findings

    Returns:
        List of processed indexed findings
    """
    try:
        if not indexed_findings:
            return []

        # Get mitigation updates from LLM
        mitigated_response = await _get_mitigation_updates(indexed_findings, contract_code)

        # Validate the response
        if not mitigated_response or not mitigated_response.updates:
            logger.warning(
                "[MITIGATION] No mitigation updates received from LLM. Using original findings."
            )
            return indexed_findings

        # Create a map of index to update for efficient lookup
        update_map = {update.index: update for update in mitigated_response.updates}

        # Apply updates to findings
        return _apply_mitigation_updates(indexed_findings, update_map)

    except Exception as e:
        logger.error(f"[MITIGATION] Error during mitigation: {e}")
        # Return original findings on error
        return indexed_findings


async def _get_mitigation_updates(
    indexed_findings: List[IndexedFinding],
    contract_code: str,
) -> MitigationUpdateList:
    """
    Get mitigation updates from LLM for the given findings.

    Args:
        indexed_findings: List of indexed findings to analyze
        contract_code: The relevant contract code for these findings

    Returns:
        LLM response with mitigation updates
    """
    # Convert indexed findings to dictionaries for the LLM
    findings_dicts = [finding.to_dict() for finding in indexed_findings]

    # Convert findings to JSON string for the prompt
    findings_json = json.dumps(findings_dicts)

    # Prepare the mitigation prompt
    mitigation_prompt = MITIGATION_PROMPT.format(
        findings=findings_json,
        flattened_contracts=contract_code,  # Use the contract code for this group
    )

    # Send to LLM
    return await send_prompt_to_llm_async(
        model_type=LLM_UTILITY,
        messages=mitigation_prompt,
        response_model=MitigationUpdateList,
    )


def _apply_mitigation_updates(
    indexed_findings: List[IndexedFinding],
    update_map: Dict[int, MitigationUpdate],
) -> List[IndexedFinding]:
    """
    Apply mitigation updates to findings.

    Args:
        indexed_findings: List of indexed findings to update
        update_map: Map of finding index to update

    Returns:
        Updated list of indexed findings
    """
    result_findings = []
    update_count = 0
    removal_count = 0

    for indexed_finding in indexed_findings:
        original_index = indexed_finding.index

        # Check if there's an update for this finding
        if original_index in update_map:
            update = update_map[original_index]

            # Check if finding should be removed
            if update.should_be_removed:
                removal_count += 1
                continue

            # Apply severity update if different
            if update.severity != indexed_finding.finding.Severity:
                # Convert string severity to Severity enum
                severity_enum = Severity.validate(update.severity)
                indexed_finding.finding.Severity = severity_enum
                update_count += 1

            # Save comments update if present
            if update.comments:
                indexed_finding.finding.Mitigation = update.comments

        # Add to result list (unless removed)
        result_findings.append(indexed_finding)

    logger.info(
        f"[MITIGATION] Mitigation completed: Updated {update_count} findings, removed {removal_count} findings."
    )
    return result_findings
