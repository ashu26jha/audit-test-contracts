from typing import Optional

from pydantic import BaseModel, HttpUrl


class FuzzerRequest(BaseModel):
    github_url: HttpUrl
    oauth_token: Optional[str] = None


class FuzzerResponse(BaseModel):
    fuzz_test: Optional[str] = None
    fuzz_results: Optional[str] = None
    analysis: Optional[str] = None
    error: Optional[str] = None
