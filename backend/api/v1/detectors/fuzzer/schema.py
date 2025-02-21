from typing import List, Optional

from pydantic import BaseModel, Field, HttpUrl

from core.models.scan import Finding
from core.schemas.scan_schema import SetupResult


class FuzzTestResult(BaseModel):
    fuzz_test: Optional[str] = None
    fuzz_results: Optional[str] = None
    findings: List[Finding] = Field(..., description="The result of the fuzz test")


class FuzzerResponse(BaseModel):
    message: str
    status: str
    data: Optional[FuzzTestResult] = None
    error: Optional[str] = None


class FuzzerRequest(BaseModel):
    github_url: HttpUrl
    oauth_token: Optional[str] = None
    selected_contracts: Optional[List[str]] = None
    setup_result: Optional[SetupResult] = None
