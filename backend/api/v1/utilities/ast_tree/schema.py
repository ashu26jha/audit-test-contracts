from typing import Annotated, Dict, List

from pydantic import BaseModel, Field, field_validator


class Parameter(BaseModel):
    """Parameter of a function"""

    name: str
    type: str


class FunctionCall(BaseModel):
    """Represents a function in a contract and its internal calls."""

    visibility: str = Field(
        ...,
        pattern="^(public|private|internal|external)$",
        description="Function visibility in Solidity",
    )
    modifiers: List[str] = Field(
        default_factory=list, description="List of modifiers for the function"
    )
    parameters: List[Parameter] = Field(
        default_factory=list, description="List of parameters for the function"
    )
    calls: List[str] = Field(
        default_factory=list, description="List of functions called within this function"
    )


class ContractAST(BaseModel):
    """Represents the internal call tree for a Solidity contract."""

    functions: Dict[str, FunctionCall] = Field(
        default_factory=dict, description="Mapping of function names to their details"
    )
    dependencies: List[str] = Field(
        default_factory=list, description="Other contract files or libraries used"
    )

    @field_validator("dependencies")
    def validate_dependency_extension(cls, values: List[str]) -> List[str]:
        """Ensure all dependencies have a .sol extension."""
        for value in values:
            if not isinstance(value, str) or not value.endswith(".sol"):
                raise ValueError(
                    f"Invalid dependency: {value}. All dependencies must have a `.sol` extension."
                )
        return values


class ProjectAST(BaseModel):
    """Represents the AST-like structure for an entire Solidity project."""

    contracts: Dict[str, ContractAST] = Field(
        ..., description="Mapping of Solidity file names to their contract structures"
    )

    @field_validator("contracts")
    def validate_contract_names(cls, contracts: Dict[str, ContractAST]):
        """Ensure all contract filenames have a `.sol` extension."""
        for filename in contracts.keys():
            if not filename.endswith(".sol"):
                raise ValueError(
                    f"Invalid contract name: {filename}. All contracts must have a `.sol` extension."
                )
        return contracts


class ASTTreeRequest(BaseModel):
    github_url: str = Field(description="The github url of the contract")
    contracts_in_scope: Annotated[
        List[str],
        Field(
            description="List of contract file paths to analyze (e.g., ['src/ContestManager.sol', 'src/Pot.sol'])"
        ),
    ]

    @field_validator("contracts_in_scope")
    def validate_contract_paths(cls, contracts: List[str]):
        """Ensure all contract paths have a `.sol` extension."""
        for path in contracts:
            if not path.endswith(".sol"):
                raise ValueError(
                    f"Invalid contract path: {path}. All contracts must have a `.sol` extension."
                )
        return contracts


class ASTTreeResponse(BaseModel):
    ast_tree: ProjectAST
