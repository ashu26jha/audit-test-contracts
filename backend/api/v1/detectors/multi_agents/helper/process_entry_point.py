from typing import List, Optional

from api.v1.detectors.multi_agents.helper.agents import (
    AnalyzerAgent,
    ValidatorAgent,
    WhiteHatAgent,
)
from api.v1.detectors.multi_agents.schema import EntryPoint
from api.v1.utilities.invariants.service import generate_invariants
from core.models.scan import Finding
from core.utils.logger import logger


async def process_entry_point(
    flattened_contracts: str,
    entry_point: EntryPoint,
    iterations_per_entrypoint: int,
    docs: Optional[str] = None,
) -> List[Finding]:
    """
    Process a single entry point through a group of agents.

    Args:
        flattened_contracts: The complete Solidity code
        entry_point: Entry point to analyze

    Returns:
        List of validated findings for this entry point
    """
    try:
        findings: List[Finding] = []
        max_validation_attempts = iterations_per_entrypoint

        # 1. Generate invariants for the entry point
        invariants = await generate_invariants(
            contracts_in_scope=[entry_point.contract_name],
            flattened_contracts=flattened_contracts,
            max_invariants=10,
        )

        # 2. Initialize Analyzer Agent and start entry point analysis
        logger.info(
            f"[MultiAgents] Starting entry point analysis agent for {entry_point.function_name}()..."
        )

        analyzer = AnalyzerAgent(flattened_contracts=flattened_contracts, entry_point=entry_point)
        analysis = await analyzer.run()

        # Initialize conversation history (only contains previous validations when available)
        conversation_history = ""

        # 3. Validation loop
        attempt = 0
        while attempt < max_validation_attempts:
            # 4. Get exploit from hacker
            logger.info(
                f"[MultiAgent] Starting white-hat agent attempt {attempt + 1} for {entry_point.function_name}()..."
            )

            hacker = WhiteHatAgent(
                flattened_contracts=flattened_contracts,
                entry_point=entry_point,
                analysis=analysis,
                invariants=invariants.invariants,
                history=conversation_history,
                previous_findings=findings,
                docs=docs,
            )
            exploit = await hacker.run()

            # 5. Validate the exploit
            logger.info(
                f"[MultiAgents] Starting validator agent attempt {attempt + 1} for {entry_point.function_name}()..."
            )

            validator = ValidatorAgent(
                flattened_contracts=flattened_contracts,
                entry_point=entry_point,
                exploit=exploit,
            )
            validation = await validator.run()

            # Append finding validation to conversation history so white hat can see it
            conversation_history += _format_conversation_entry(
                f"Finding number {attempt + 1} validation:", str(validation)
            )

            if validation.is_valid:
                findings.append(validation.final_finding)
                message = f"Valid finding identified in attempt {attempt + 1}."
            else:
                message = f"Invalid finding in attempt {attempt + 1}."

            # Add attempt context
            if attempt < max_validation_attempts - 1:
                message += f" Proceeding with attempt {attempt + 2}..."
            conversation_history += _format_conversation_entry("System", message)

            attempt += 1

        logger.info(
            f"[MultiAgents] Entry point {entry_point.function_name}() completed with {len(findings)} findings"
        )
        return findings

    except Exception as e:
        logger.error(f"Error processing entry point {entry_point.function_name}: {str(e)}")
        return []  # Silent failure for individual entry points


def _format_conversation_entry(role: str, message: str) -> str:
    return f"[{role}]\n{message}\n\n---\n\n"
