from typing import List, Optional

from pydantic import BaseModel, HttpUrl

from core.utils.severity import Severity


class StaticAnalyzerRequest(BaseModel):
    github_url: HttpUrl
    contracts: Optional[List[str]] = None
    oauth_token: Optional[str] = None
    contracts: Optional[List[str]] = None


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


class StaticAnalysisOutput(BaseModel):
    total_findings: int
    severity_counts: SeverityCounts
    findings: List[TransformedSlitherResult]


class StaticAnalyzerResponse(BaseModel):
    message: str
    status: str
    project_type: str
    environment_setup: str
    static_analysis_output: StaticAnalysisOutput
