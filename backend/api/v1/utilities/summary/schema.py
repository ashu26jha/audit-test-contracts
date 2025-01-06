from pydantic import BaseModel, Field


class SummaryRequest(BaseModel):
    """Request model for generating a summary of a contract."""

    contracts: str = Field(..., description="The contract text to summarize.")


class SummaryResponse(BaseModel):
    """Response model for generating a summary of a contract."""

    summary: str = Field(..., description="The generated summary of the contract.")
    type: str = Field(..., description="The category/type of the contract.")
