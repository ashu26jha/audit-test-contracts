from enum import Enum
from typing import List, Optional

from pydantic import BaseModel, HttpUrl


class StaticAnalyzerRequest(BaseModel):
    github_url: HttpUrl
    oauth_token: Optional[str] = None


class Severity(str, Enum):
    HIGH = "High"
    MEDIUM = "Medium"
    LOW = "Low"
    INFORMATIONAL = "Informational"
    OPTIMIZATION = "Optimization"


class TransformedSlitherResult(BaseModel):
    Issue: str
    OriginalIssue: str
    Severity: Severity
    Confidence: str
    Contracts: List[str]
    Description: str
    Lines: str


class SeverityCounts(BaseModel):
    High: int = 0
    Medium: int = 0
    Low: int = 0
    Informational: int = 0
    Optimization: int = 0


class SlitherOutput(BaseModel):
    total_findings: int
    severity_counts: SeverityCounts
    findings: List[TransformedSlitherResult]


class StaticAnalyzerResponse(BaseModel):
    message: str
    status: str
    project_type: str
    contract_folders: List[str]
    environment_setup: str
    slither_output: SlitherOutput
