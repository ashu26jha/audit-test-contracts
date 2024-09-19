from pydantic import BaseModel, Field
from typing import Optional

class FuzzerRequest(BaseModel):
    contract: str = Field(..., description="Solidity contract content")
    contract_name: str = Field(..., description="Name of the contract file")

class FuzzerResponse(BaseModel):
    contract_name: str
    fuzz_test: Optional[str] = None
    fuzz_results: Optional[str] = None
    analysis: Optional[str] = None
    error: Optional[str] = None
