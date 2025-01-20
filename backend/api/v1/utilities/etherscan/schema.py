from typing import Dict, List

from pydantic import BaseModel, Field, field_validator

from core.utils.validate import is_valid_eth_address


class GetContractSourceCodeRequest(BaseModel):
    """Request model for getting contract source code."""

    contractAddress: str = Field(..., description="Contract address to fetch source code for")
    chainId: int = Field(None, description="Chain ID of the network")
    userEmail: str = Field(None, description="User email to send the source code to")

    @field_validator("contractAddress")
    @classmethod
    def validate_ethereum_address(cls, value: str) -> str:
        if not is_valid_eth_address(value):
            raise ValueError("Invalid Ethereum address format")
        return value


class RemoveLibraryResponse(BaseModel):
    """Response model for removing libraries."""

    libraries_to_remove: List[str] = Field(..., description="Libraries to remove")


class ContractSourceCode(BaseModel):
    """Model representing the source code content and token length for a contract file."""

    content: str = Field(..., description="The source code content of the contract")
    token_length: int = Field(..., description="The token length of the contract content")


# Simple dictionary type mapping contract names to their source code
ContractSourceCodeResponse = Dict[str, ContractSourceCode]
