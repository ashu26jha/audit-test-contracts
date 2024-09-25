from pydantic import BaseModel, Field


class GeneratePdfRequest(BaseModel):
    scan_id: str = Field(..., description="The ID of the scan to generate a PDF for")


class GeneratePdfResponse(BaseModel):
    pdf_url: str = Field(..., description="The URL of the generated PDF")
