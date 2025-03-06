from typing import List

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


class BuildQueriesRequest(BaseModel):
    github_url: str
    contracts_in_scope: List[str]
    contracts: str
    num_queries: int


class BuildQueriesResult(BaseModel):
    queries: List[str]
