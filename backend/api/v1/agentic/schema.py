from typing import List
from uuid import UUID

from pydantic import BaseModel, Field, field_validator
from web3 import Web3


class PerAddressAgenticRequest(BaseModel):
    """Input request for agentic scan from a contract address"""

    contractAddress: str = Field(..., description="Contract address to scan")
    chainID: int = Field(..., description="Chain ID to scan")

    @field_validator("contractAddress")
    @classmethod
    def validate_ethereum_address(cls, value):
        if not Web3.is_address(value):  # Ensures it's a valid Ethereum address
            raise ValueError("Invalid Ethereum address format")
        return Web3.to_checksum_address(value)


class PerAddressAgenticResponse(BaseModel):
    scan_id: UUID = Field(..., description="Unique identifier for the scan")


class AgenticScanContext(BaseModel):
    """Context maintaining the state throughout the scan process."""

    # Core identifiers
    scan_id: UUID

    # Scan configuration
    contract_address: str
    chain_id: int
    contract_files: List[str]
    flattened_contracts: str

    class Config:
        arbitrary_types_allowed = True
