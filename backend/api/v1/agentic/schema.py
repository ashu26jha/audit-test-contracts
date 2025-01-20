from typing import List
from uuid import UUID

from pydantic import BaseModel, Field, field_validator


class PerAddressAgenticRequest(BaseModel):
    """Input request for agentic scan from a contract address"""

    contractAddress: str = Field(..., description="Contract address to scan")
    chainId: int = Field(None, description="Chain ID to scan")
    userEmail: str = Field(None, description="User email to send scan results to")

    @field_validator("contractAddress")
    @classmethod
    def validate_ethereum_address(cls, value: str) -> str:
        if not is_valid_eth_address(value):
            raise ValueError("Invalid Ethereum address format")
        return value  # Return as-is since we validated the checksum


class PerAddressAgenticResponse(BaseModel):
    scan_id: UUID = Field(..., description="Unique identifier for the scan")


class AgenticScanContext(BaseModel):
    """Context maintaining the state throughout the scan process."""

    # Core identifiers
    scan_id: UUID
    user_email: str

    # Scan configuration
    contract_address: str
    chain_id: int
    contract_files: List[str]
    flattened_contracts: str

    class Config:
        arbitrary_types_allowed = True


def is_valid_eth_address(address: str) -> bool:
    """Validates basic Ethereum address format.

    Only checks if the address:
    1. Starts with '0x'
    2. Is followed by 40 hexadecimal characters
    3. Has total length of 42 characters
    """
    # Check if it's a string and has basic format (0x followed by 40 chars)
    if not isinstance(address, str) or not address.startswith("0x") or len(address) != 42:
        return False

    # Check if all characters after 0x are valid hex
    try:
        int(address[2:], 16)
        return True
    except ValueError:
        return False
