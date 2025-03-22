from typing import List, Optional

from api.v1.detectors.multi_agents.schema import (
    Analysis,
    EntryPoint,
    Exploit,
    ValidationResult,
)
from api.v1.utilities.invariants.schema import Invariant
from config.prompts.multiagent_prompts import (
    ANALYZER_PROMPT,
    VALIDATOR_PROMPT,
    WHITE_HAT_PROMPT,
)
from config.settings import LLM_SCAN_3, LLM_UTILITY
from core.models.scan import Finding
from core.schemas.agent import Agent


class AnalyzerAgent(Agent[Analysis]):
    """Agent responsible for analyzing entry points in detail"""

    def __init__(self, flattened_contracts: str, entry_point: EntryPoint):
        # Create the prompt first
        prompt = ANALYZER_PROMPT.format(
            flattened_contracts=flattened_contracts,
            function_name=entry_point.function_name,
            contract_name=entry_point.contract_name,
            visibility=entry_point.visibility,
            modifiers=", ".join(entry_point.modifiers),
        )

        # Initialize Agent
        super().__init__(
            name="Entry Point Analyzer",
            description="Analyzes smart contract entry points for potential vulnerabilities",
            prompt=prompt,
            model=LLM_UTILITY,
            response_model=Analysis,
        )


class WhiteHatAgent(Agent[Exploit]):
    """Agent responsible for finding potential exploits"""

    NON_GIVEN: str = "Non-Given"

    def __init__(
        self,
        flattened_contracts: str,
        entry_point: EntryPoint,
        analysis: Analysis,
        invariants: list[Invariant],
        history: str,
        previous_findings: Optional[List[Finding]] = NON_GIVEN,
        docs: Optional[str] = NON_GIVEN,
        duckduckgo_analysis: Optional[str] = NON_GIVEN,
    ):
        # Create the prompt first
        prompt = WHITE_HAT_PROMPT.format(
            function_name=entry_point.function_name,
            contract_name=entry_point.contract_name,
            docs=docs,
            analysis=analysis,
            duckduckgo_results=duckduckgo_analysis,
            invariants=invariants,
            previous_findings=previous_findings,
            history=history,
            flattened_contracts=flattened_contracts,
        )

        # Initialize Agent
        super().__init__(
            name="White Hat Hacker",
            description="Identifies potential exploits in smart contracts",
            prompt=prompt,
            model=LLM_SCAN_3,
            response_model=Exploit,
        )


class ValidatorAgent(Agent[ValidationResult]):
    """Agent responsible for validating potential exploits"""

    def __init__(
        self,
        flattened_contracts: str,
        entry_point: EntryPoint,
        exploit: Exploit,
        duckduckgo_analysis: Optional[str] = "Non-Given",
    ):
        # Create the prompt first
        prompt = VALIDATOR_PROMPT.format(
            function_name=entry_point.function_name,
            contract_name=entry_point.contract_name,
            line_number=entry_point.line_number,
            exploit=exploit,
            flattened_contracts=flattened_contracts,
            duckduckgo_results=duckduckgo_analysis,
        )

        # Initialize Agent
        super().__init__(
            name="Exploit Validator",
            description="Validates potential smart contract exploits",
            prompt=prompt,
            model=LLM_UTILITY,
            response_model=ValidationResult,
        )
