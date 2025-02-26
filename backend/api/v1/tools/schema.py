from pydantic import BaseModel


class DuckDuckGoSearchRequest(BaseModel):
    query: str


class DuckDuckGoResponse(BaseModel):
    title: str
    href: str
    body: str


class DuckDuckGoSearchResult(BaseModel):
    results: list[DuckDuckGoResponse]


class JinaParseRequest(BaseModel):
    url: str


class JinaParseResult(BaseModel):
    response: str


class PerplexitySearchRequest(BaseModel):
    query: str


class PerplexitySearchResult(BaseModel):
    response: str
