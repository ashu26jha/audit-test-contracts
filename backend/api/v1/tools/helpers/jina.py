from core.utils.errors import HTTPClientError
from core.utils.http_client import get_http_client
from core.utils.logger import logger

BASE_URL = "https://r.jina.ai"


async def jina_parse(url: str) -> str:
    try:
        jina_url = f"{BASE_URL}/{url}"
        async with get_http_client(timeout=60.0) as client:
            response = await client.get(jina_url)
            return response.text
    except HTTPClientError as e:
        logger.warning(f"[Jina] HTTP error parsing {url}: {e.message}")
        return f"Error parsing {url}: {e.message}"
    except Exception as e:
        logger.exception(f"[Jina] Unexpected error parsing {url}: {e}")
        return f"Error parsing {url}: {e}"


def get_description() -> str:
    """
    Returns the description for the jina_parse tool.
    """
    return "jina_parse: Parses content from URLs using Jina's API and returns the result text."
