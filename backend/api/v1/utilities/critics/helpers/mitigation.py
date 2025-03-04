import json
from typing import List

from langfuse.decorators import observe

from api.v1.utilities.critics.schema import MitigationUpdateList
from config.prompts.mitigation_prompts import MITIGATION_PROMPT
from config.settings import LLM_UTILITY
from core.llm.send_prompt_to_llm import send_prompt_to_llm_async
from core.models.scan import Finding
from core.utils.logger import logger
from core.utils.severity import Severity


@observe(name="mitigate_findings")
async def mitigate_findings_async(
    findings: List[Finding],
    flattened_contracts: str,
) -> List[Finding]:
    """
    Process findings through mitigation analysis to adjust severity ratings,
    add additional context, and optionally remove false positives.

    Args:
        findings: List of findings to analyze
        flattened_contracts: Flattened contract code for context

    Returns:
        List[Finding]: Findings with potentially adjusted severities,
        with false positives removed, or original findings if validation fails
    """
    logger.info(f"Starting mitigation analysis for {len(findings)} findings...")

    try:
        if not findings:
            return []

        # Add index to each finding
        indexed_findings = []
        for idx, finding in enumerate(findings):
            finding_dict = finding.model_dump(mode="json")
            finding_dict["index"] = idx
            indexed_findings.append(finding_dict)

        # Convert findings to JSON string for the prompt
        findings_json = json.dumps(indexed_findings)

        # Prepare the mitigation prompt
        mitigation_prompt = MITIGATION_PROMPT.format(
            findings=findings_json,
            flattened_contracts=flattened_contracts,
        )

        # Send to LLM
        mitigated_response = await send_prompt_to_llm_async(
            model_type=LLM_UTILITY,
            messages=mitigation_prompt,
            response_model=MitigationUpdateList,
        )

        # Validate the response
        if not mitigated_response or not mitigated_response.updates:
            logger.warning("No mitigation updates received from LLM. Using original findings.")
            return findings

        # Copy original findings list so we don't modify the input
        updated_findings = findings.copy()

        # Track which findings should be removed (by index)
        to_remove_indexes = set()

        # Apply updates to findings
        max_index = len(findings) - 1
        update_count = 0
        removal_count = 0

        for update in mitigated_response.updates:
            if 0 <= update.index <= max_index:
                # Check if finding should be removed
                if update.should_be_removed:
                    to_remove_indexes.add(update.index)
                    removal_count += 1
                    continue

                # Apply severity update
                if update.severity != updated_findings[update.index].Severity:
                    # Convert string severity to Severity enum
                    severity_enum = Severity.validate(update.severity)
                    updated_findings[update.index].Severity = severity_enum
                    update_count += 1

                # Apply comments update if present
                if update.comments:
                    if updated_findings[update.index].Description:
                        updated_findings[
                            update.index
                        ].Description += f"\n\nMitigation Analysis: {update.comments}"
                    else:
                        updated_findings[update.index].Description = (
                            f"Mitigation Analysis: {update.comments}"
                        )
            else:
                logger.warning(
                    f"Invalid index {update.index} in mitigation response. Ignoring this update."
                )

        # Remove findings that were marked for removal (in reverse order to maintain correct indices)
        final_findings = [f for i, f in enumerate(updated_findings) if i not in to_remove_indexes]

        logger.info(
            f"Mitigation completed successfully. Updated {update_count} findings, removed {removal_count} findings."
        )
        return final_findings

    except Exception as e:
        logger.error(f"Error during findings mitigation: {e}")
        logger.info("Falling back to original findings without mitigation")
        return findings
