from dataclasses import dataclass
from typing import Dict, Optional
from uuid import UUID

from pydantic import BaseModel, ConfigDict, Field, field_validator

from core.schemas.context_protocols import ChainContext, UserContext
from core.schemas.scan_schema import BaseScanContext, ScanType
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


@dataclass(kw_only=True)
class AgenticScanContext(BaseScanContext):
    """Context for Agentic scans with chain and user capabilities."""

    user_email: str
    user_name: str
    contract_address: str
    chain_id: int

    user_id: str = "agentic"
    user_access_token: str = "test_access_token"
    scan_number: int = 1
    scan_type: ScanType = ScanType.AGENTIC
    contracts_dict: Optional[Dict[str, str]] = None

    model_config = ConfigDict(arbitrary_types_allowed=True)
    _supports = (UserContext, ChainContext)
