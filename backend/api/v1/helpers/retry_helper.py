import asyncio
from typing import Any, Callable, TypeVar

from common.logger import logger
from config.settings import DELAY, MAX_RETRIES

T = TypeVar("T")


async def retry_async_operation(operation: Callable[..., T], *args: Any, **kwargs: Any) -> T:
    """
    Retries an asynchronous operation with exponential backoff.

    Args:
        operation: The async function to retry.
        *args: Positional arguments to pass to the operation.
        **kwargs: Keyword arguments to pass to the operation.

    Returns:
        The result of the operation if successful.

    Raises:
        Exception: If all retry attempts fail.
    """
    for attempt in range(MAX_RETRIES):
        try:
            return await operation(*args, **kwargs)
        except Exception as e:
            if attempt == MAX_RETRIES - 1:
                logger.exception(f"All {MAX_RETRIES} attempts failed. Last error: {str(e)}")
                raise
            wait_time = DELAY * (2**attempt)
            logger.warning(f"Attempt {attempt + 1} failed. Retrying in {wait_time:.2f} seconds...")
            await asyncio.sleep(wait_time)
