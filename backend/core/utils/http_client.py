from contextlib import asynccontextmanager
from typing import AsyncGenerator

import httpx
from httpx import AsyncClient

from core.utils.errors import HTTPClientError
from core.utils.logger import logger


@asynccontextmanager
async def get_http_client(
    timeout: float = 30.0,
    follow_redirects: bool = True,
) -> AsyncGenerator[AsyncClient, None]:
    """
    Async context manager for getting an HTTP client with default configuration.

    Usage:
        async with get_http_client() as client:
            response = await client.get("https://api.example.com")

    Args:
        timeout: Request timeout in seconds
        follow_redirects: Whether to follow redirects
    """
    try:
        async with AsyncClient(
            timeout=timeout,
            follow_redirects=follow_redirects,
            headers={"Accept": "application/json"},
        ) as client:
            yield client
    except httpx.TimeoutException as e:
        logger.error(f"HTTP request timed out: {str(e)}")
        raise HTTPClientError(
            message="Request timed out", details={"error": str(e), "type": "timeout"}
        )
    except httpx.RequestError as e:
        logger.error(f"HTTP request failed: {str(e)}")
        raise HTTPClientError(
            message="Request failed", details={"error": str(e), "type": "request_error"}
        )
    except Exception as e:
        logger.error(f"Unexpected error during HTTP request: {str(e)}")
        raise HTTPClientError(
            message="Unexpected error during HTTP request",
            details={"error": str(e), "type": "unexpected"},
        )
