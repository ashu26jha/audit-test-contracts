from core.utils.errors import HTTPClientError, ParsingError
from core.utils.http_client import get_http_client
from core.utils.logger import logger

BASE_URL = "https://r.jina.ai"


async def jina_parse(url: str) -> str:
    """
    Parse content from a URL using Jina's API.

    Args:
        url: The URL to parse

    Returns:
        str: The parsed content

    Raises:
        HTTPClientError: When there's an HTTP error during parsing
        ParsingError: For other parsing errors
    """
    try:
        jina_url = f"{BASE_URL}/{url}"
        async with get_http_client(timeout=60.0) as client:
            response = await client.get(jina_url)
            return response.text
    except HTTPClientError as e:
        logger.warning(f"[Jina] HTTP error parsing {url}: {e.message}")
        # Let HTTP errors propagate upward to be handled by the service
        raise
    except Exception as e:
        logger.exception(f"[Jina] Unexpected error parsing {url}: {e}")
        raise ParsingError(
            message=f"Error parsing URL: {url}", details={"error": str(e), "url": url}
        )


def get_description() -> str:
    """
    Returns the description for the jina_parse tool.
    """
    return "jina_parse: Parses content from URLs using Jina's API and returns the result text."
