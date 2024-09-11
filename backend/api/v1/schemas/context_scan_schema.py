from pydantic import BaseModel, Field

class ContextScanRequest(BaseModel):
    text: str = Field(..., description="The text to be scanned")
    context: str = Field(..., description="The context to be used for scanning")

class ContextScanResponse(BaseModel):
    result: dict = Field(..., description="The result of the context scan")