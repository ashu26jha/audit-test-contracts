from typing import List, Optional

from pydantic import BaseModel, HttpUrl


class FuzzerRequest(BaseModel):
    github_url: HttpUrl
    oauth_token: Optional[str] = None


class FuzzTestResult(BaseModel):
    fuzz_test: Optional[str] = None
    fuzz_results: Optional[str] = None
    analysis: Optional[str] = None


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
