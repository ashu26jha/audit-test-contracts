from fastapi import APIRouter

# Import schemas for each tool
from .schema import (
    DuckDuckGoSearchRequest,
    JinaParseRequest,
    JinaParseResult,
    PerplexitySearchRequest,
    PerplexitySearchResult,
)

# Import helper service functions from the new helper folder
from .service import (
    duckduckgo_search_service,
    jina_parse_service,
    perplexity_search_service,
)

router = APIRouter(tags=["Tools"], prefix="/tools")


@router.post("/duckduckgo-search")
async def duckduckgo_search_route(request: DuckDuckGoSearchRequest):
    results = await duckduckgo_search_service(request.query)
    return results


@router.post("/jina-parse", response_model=JinaParseResult)
async def jina_parse_route(request: JinaParseRequest):
    response = await jina_parse_service(request.url)
    return JinaParseResult(response=response)


@router.post("/perplexity-search", response_model=PerplexitySearchResult)
async def perplexity_search_route(request: PerplexitySearchRequest):
    response = await perplexity_search_service(request.query)
    return PerplexitySearchResult(response=response)
