from pydantic import BaseModel, HttpUrl
from typing import Optional, Dict, Union

class FuzzerRequest(BaseModel):
    github_url: HttpUrl
    oauth_token: Optional[str] = None

class FuzzerResponse(BaseModel):
    fuzz_test: Optional[str] = None
    fuzz_results: Optional[str] = None
    analysis: Optional[str] = None
    error: Optional[str] = None