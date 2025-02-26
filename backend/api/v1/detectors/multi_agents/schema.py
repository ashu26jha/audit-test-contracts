from typing import List

from pydantic import BaseModel

from core.models.scan import Finding


class MultiAgentRequest(BaseModel):
    github_url: str
    contracts_in_scope: List[str]


class MultiAgentResponse(BaseModel):
    findings: List[Finding]


# ---------------------------------------------------
#   Entry Point Schemas
# ---------------------------------------------------


class Parameter(BaseModel):
    """Parameter of a function"""

    name: str
    type: str


class EntryPoint(BaseModel):
    """Represents a smart contract entry point"""

    function_name: str
    contract_name: str
    visibility: str
    modifiers: List[str]
    parameters: List[Parameter]
    line_number: int


class EntryPointResponse(BaseModel):
    """Response model for entry point extraction"""

    entry_points: List[EntryPoint]


class StateChange(BaseModel):
    """Represents a state change in the contract"""

    variable: str
    change_type: str
    description: str


class ValueFlow(BaseModel):
    """Represents a value flow in the contract"""

    source: str
    destination: str
    value_type: str
    conditions: List[str]


class Analysis(BaseModel):
    """Represents a detailed analysis of an entry point"""

    state_changes: List[StateChange]
    value_flows: List[ValueFlow]
    interaction_paths: List[str]
    potential_risks: List[str]
    bypass_opportunities: List[str]


# ---------------------------------------------------
#   Exploit Schemas
# ---------------------------------------------------


class Exploit(BaseModel):
    """Represents a potential exploit"""

    finding: Finding


# ---------------------------------------------------
#   Validation Schemas
# ---------------------------------------------------


class ValidationResult(BaseModel):
    """
    Represents the response from validation of a potential exploit or vulnerability.
    - is_valid: boolean indicating if the exploit is valid
    - confidence: how confident the validator is in the result ("High", "Medium", "Low")
    - comments: additional remarks or feedback for iterative improvement
    - additional_considerations: an optional list of other comments or next steps
    - final_severity: final classification of severity
    - final_finding: the validated finding, if any
    """

    is_valid: bool
    confidence: str
    comments: str
    additional_considerations: List[str]
    final_severity: str
    final_finding: Finding
