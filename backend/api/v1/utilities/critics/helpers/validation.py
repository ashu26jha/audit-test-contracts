import json
from typing import Dict, List

from langfuse.decorators import observe

from api.v1.utilities.critics.helpers.batch_processor import (
    _process_in_batches,
    calculate_optimal_batch_size,
)
from api.v1.utilities.critics.helpers.contract_grouping import process_findings_by_contract_groups
from api.v1.utilities.critics.schema import (
    CounterArgument,
    CounterArgumentsList,
    IndexedFinding,
    ValidationJudgementList,
)
from config.prompts.validation_prompts import COUNTER_ARGUMENTS_PROMPT, VALIDATION_JUDGEMENT_PROMPT
from config.settings import LLM_UTILITY, MAX_BATCHES, MIN_BATCH_SIZE
from core.llm.send_prompt_to_llm import send_prompt_to_llm_async
from core.models.scan import Finding
from core.utils.logger import logger

# Maximum number of findings to process in a single batch for validation
MAX_FINDINGS_PER_CONTRACT = 25

# Confidence score thresholds for finding validation
LOW_CONFIDENCE_THRESHOLD = 40  # Findings below this score are discarded
HIGH_CONFIDENCE_THRESHOLD = 80  # Findings above this score don't get counter-arguments added


@observe(name="[CRITICS] validate findings")
async def validate_findings_batched(
    findings: List[Finding], contract_contents: Dict[str, str]
) -> List[Finding]:
    """
    Validate and score findings using a two-step LLM analysis by contract groups.

    The validation process:
    1. Group findings by their primary contract
    2. Extract relevant code for each contract group
    3. For each group, generate counter-arguments for each finding
    4. Then, evaluate those counter-arguments to assign a detection confidence score
    5. Keep, modify, or remove findings based on detection confidence

    For large contract groups (more than MAX_FINDINGS_PER_BATCH findings),
    the findings are processed in smaller batches to manage token usage.

    Args:
        findings: List of findings to validate
        contract_contents: Dictionary mapping contract filenames to their source code

    Returns:
        List of findings after validation:
        - Findings with score < LOW_CONFIDENCE_THRESHOLD are removed
        - Findings with score LOW_CONFIDENCE_THRESHOLD-HIGH_CONFIDENCE_THRESHOLD have counter-arguments added to their description
        - Findings with score > HIGH_CONFIDENCE_THRESHOLD remain unchanged
    """
    if not findings:
        return []

    logger.info(
        f"[VALIDATION] Validating {len(findings)} findings using contract-based validation..."
    )

    # Process findings by contract groups
    return await process_findings_by_contract_groups(
        findings=findings,
        contract_contents=contract_contents,
        processor=validate_findings_with_counter_arguments,
        operation_name="validation",
    )


async def validate_findings_with_counter_arguments(
    indexed_findings: List[IndexedFinding], contract_code: str
) -> List[IndexedFinding]:
    """
    Two-step validation process that first generates counter-arguments and then judges the findings.

    For large groups (more than MAX_FINDINGS_PER_CONTRACT findings), the findings are processed in
    smaller batches to manage token usage.

    Args:
        indexed_findings: List of indexed findings to validate
        contract_code: The relevant contract code for these findings

    Returns:
        List of indexed findings after validation
    """
    try:
        if not indexed_findings:
            return []

        # Check if we need to batch process due to large number of findings
        if len(indexed_findings) > MAX_FINDINGS_PER_CONTRACT:
            return await _split_and_process_large_batch(indexed_findings, contract_code)

        # For smaller groups, process all findings together
        return await _execute_two_step_validation(indexed_findings, contract_code)

    except Exception as e:
        error_msg = f"[VALIDATION] Failed validation with counter-arguments: {str(e)}"
        logger.exception(error_msg)
        # Return original findings on error
        return indexed_findings


async def _split_and_process_large_batch(
    indexed_findings: List[IndexedFinding], contract_code: str
) -> List[IndexedFinding]:
    """
    Split and process a large group of findings in smaller batches.

    Args:
        indexed_findings: List of indexed findings to validate
        contract_code: The relevant contract code for these findings

    Returns:
        List of indexed findings after validation
    """
    total_findings = len(indexed_findings)
    logger.info(
        f"[VALIDATION] Large group detected with {total_findings} findings. Using batch processing."
    )

    # Calculate optimal batch size using the utility function
    batch_size = calculate_optimal_batch_size(
        items_count=total_findings,
        min_batch_size=MIN_BATCH_SIZE,
        max_batches=MAX_BATCHES,
    )

    # Cap batch size at MAX_FINDINGS_PER_CONTRACT
    batch_size = min(batch_size, MAX_FINDINGS_PER_CONTRACT)

    # Use the generic batch processing function with our validation processor
    async def process_batch(batch):
        return await _execute_two_step_validation(batch, contract_code)

    return await _process_in_batches(
        items=indexed_findings,
        processor=process_batch,
        batch_size=batch_size,
        description="findings",
        hierarchical=False,
    )


async def _execute_two_step_validation(
    indexed_findings: List[IndexedFinding], contract_code: str
) -> List[IndexedFinding]:
    """
    Execute the two-step validation process on a batch of findings:
    1. Generate counter-arguments
    2. Judge findings based on counter-arguments

    Args:
        indexed_findings: List of indexed findings to validate
        contract_code: The relevant contract code for these findings

    Returns:
        List of indexed findings after validation
    """
    # Step 1: Generate counter-arguments for each finding
    counter_arguments = await _generate_counter_arguments(indexed_findings, contract_code)
    if not counter_arguments or not counter_arguments.counter_arguments:
        logger.warning("[VALIDATION] No counter-arguments generated, keeping original findings")
        return indexed_findings

    # Create a map of index to counter-argument for efficient lookup
    counter_arg_map = {arg.index: arg for arg in counter_arguments.counter_arguments}

    # Step 2: Judge the findings based on counter-arguments
    judgements = await _judge_findings_with_counter_arguments(
        indexed_findings, counter_arguments.counter_arguments, contract_code
    )

    if not judgements or not judgements.judgements:
        logger.warning("[VALIDATION] No judgements returned, keeping original findings")
        return indexed_findings

    # Create a map of index to judgement for efficient lookup
    judgement_map = {j.index: j for j in judgements.judgements}

    # Process findings based on judgements
    validated_findings = []

    for indexed_finding in indexed_findings:
        finding = indexed_finding.finding
        index = indexed_finding.index

        if index in judgement_map:
            judgement = judgement_map[index]
            confidence = judgement.detection_confidence

            # Decision based on confidence score
            if confidence < LOW_CONFIDENCE_THRESHOLD:
                # Discard findings with low confidence - log only these findings and their justification
                logger.info(
                    f"[VALIDATION] Discarding finding #{index} - '{finding.Issue}' due to low confidence ({confidence})"
                )
                logger.info(f"[VALIDATION] Discard justification: {judgement.justification}")
                continue
            elif confidence >= LOW_CONFIDENCE_THRESHOLD and confidence <= HIGH_CONFIDENCE_THRESHOLD:
                # For findings with medium confidence, add counter-arguments to description
                if index in counter_arg_map:
                    _add_counter_arguments_to_finding(finding, counter_arg_map[index], confidence)

            validated_findings.append(indexed_finding)
        else:
            # Keep findings without judgements
            logger.info(f"[VALIDATION] No judgement available for finding #{index}, keeping it")
            validated_findings.append(indexed_finding)

    return validated_findings


async def _generate_counter_arguments(
    indexed_findings: List[IndexedFinding], contract_code: str
) -> CounterArgumentsList:
    """
    Generate counter-arguments for each finding using LLM.

    Args:
        indexed_findings: List of indexed findings
        contract_code: The relevant contract code

    Returns:
        List of counter-arguments
    """
    # Convert indexed findings to dictionaries for the LLM
    findings_dicts = [finding.to_dict() for finding in indexed_findings]

    # Format findings for LLM
    formatted_findings = json.dumps(findings_dicts)
    prompt = COUNTER_ARGUMENTS_PROMPT.format(
        vulnerabilities=formatted_findings, contract_code=contract_code
    )

    # Send to LLM
    return await send_prompt_to_llm_async(
        model_type=LLM_UTILITY,
        messages=prompt,
        response_model=CounterArgumentsList,
    )


def _add_counter_arguments_to_finding(
    finding: Finding, counter_arg: CounterArgument, confidence: int
) -> None:
    """
    Add counter-arguments to a finding's description.

    Args:
        finding: The finding to modify
        counter_arg: The counter-arguments to add
        confidence: The confidence score
    """
    finding.Description += "\n\nPotential issues with this finding:\n"
    finding.Description += f"1. {counter_arg.argument_1}\n"
    finding.Description += f"2. {counter_arg.argument_2}\n"
    finding.Description += f"\nDetection confidence: {confidence}/100."


async def _judge_findings_with_counter_arguments(
    indexed_findings: List[IndexedFinding],
    counter_arguments: List[CounterArgument],
    contract_code: str,
) -> ValidationJudgementList:
    """
    Judge findings based on counter-arguments.

    Args:
        indexed_findings: List of indexed findings
        counter_arguments: List of counter-arguments
        contract_code: The relevant contract code

    Returns:
        List of judgements with confidence scores
    """
    # Convert indexed findings to dictionaries for the LLM
    findings_dicts = [finding.to_dict() for finding in indexed_findings]
    counter_args_dicts = [
        {"index": arg.index, "argument_1": arg.argument_1, "argument_2": arg.argument_2}
        for arg in counter_arguments
    ]

    # Format for LLM
    formatted_findings = json.dumps(findings_dicts)
    formatted_counter_args = json.dumps(counter_args_dicts)

    prompt = VALIDATION_JUDGEMENT_PROMPT.format(
        vulnerabilities=formatted_findings,
        counter_arguments=formatted_counter_args,
        contract_code=contract_code,
    )

    # Send to LLM
    return await send_prompt_to_llm_async(
        model_type=LLM_UTILITY,
        messages=prompt,
        response_model=ValidationJudgementList,
    )
