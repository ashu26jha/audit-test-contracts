from typing import List, Optional

from pydantic import BaseModel, Field, HttpUrl

from api.v1.schemas.context_scan_schema import Finding


class FuzzTestResult(BaseModel):
    fuzz_test: Optional[str] = None
    fuzz_results: Optional[str] = None
    findings: List[Finding] = Field(..., description="The result of the fuzz test")


class FuzzerResponse(BaseModel):
    message: str
    status: str
    data: Optional[FuzzTestResult] = None
    error: Optional[str] = None


class SetupResult(BaseModel):
    project_dir: str
    project_type: str
    project_structure: str
    remappings: Optional[List[str]] = None


class FuzzerRequest(BaseModel):
    github_url: HttpUrl
    oauth_token: Optional[str] = None
    selected_contracts: Optional[List[str]] = None
    setup_result: Optional[SetupResult] = None


class InvariantResponse(BaseModel):
    description: str = Field(..., description="The description of the invariants")
    function: str = Field(..., description="The function name of the invariant")
    condition: str = Field(..., description="The condition of the invariant")


class InvariantsList(BaseModel):
    invariants: List[InvariantResponse]
