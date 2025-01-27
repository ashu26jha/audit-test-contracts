from typing import List
from uuid import UUID

from pydantic import BaseModel, ConfigDict, Field, field_validator

from core.utils.validate import is_valid_eth_address


class PerAddressAgenticRequest(BaseModel):
    """Input request for agentic scan from a contract address"""

    contractAddress: str = Field(..., description="Contract address to scan")
    chainId: int = Field(..., description="Chain ID to scan")
    userEmail: str = Field(..., description="User email to send scan results to")
    userName: str = Field(..., description="Twitter handle of the user")

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
    user_name: str

    # Scan configuration
    contract_address: str
    chain_id: int
    contract_files: List[str]
    flattened_contracts: str

    model_config = ConfigDict(arbitrary_types_allowed=True)
