from typing import List, Optional

from pydantic import BaseModel, HttpUrl, Field

class Finding(BaseModel):
    Issue: str = Field(..., description="A short description of the vulnerability or issue")
    Severity: str = Field(..., description="Severity level of the issue")
    Contracts: List[str] = Field(..., description="List of affected contract names")
    Description: str = Field(..., description="Detailed description of the issue")
    Recommendation: Optional[str] = Field(None, description="Suggested fix for the issue.")

class FuzzTestResult(BaseModel):
    fuzz_test: Optional[str] = None
    fuzz_results: Optional[str] = None
    analysis: Optional[str] = None
    findings: List[Finding] = Field(..., description="The result of the fuzz test")


class FuzzerResponse(BaseModel):
    message: str
    status: str
    data: Optional[FuzzTestResult] = None
    error: Optional[str] = None


class SetupResult(BaseModel):
    project_dir: str
    contract_folders: List[str]
    project_type: str
    project_path: str
    solc_version: str
    remappings: List[str]

class FuzzerRequest(BaseModel):
    github_url: HttpUrl
    oauth_token: Optional[str] = None
    selected_contracts: List[str]
    setup_result: Optional[SetupResult] = None
