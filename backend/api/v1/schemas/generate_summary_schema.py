from pydantic import BaseModel, Field


class SummaryRequest(BaseModel):
    contracts: str = Field(..., description="The contract text to summarize.")


class SummaryResponse(BaseModel):
    summary: str = Field(..., description="The generated summary of the contract.")
    type: str = Field(..., description="The category/type of the contract.")
