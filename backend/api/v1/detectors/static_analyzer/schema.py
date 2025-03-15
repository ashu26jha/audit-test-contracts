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
    Detector: Optional[str] = None
