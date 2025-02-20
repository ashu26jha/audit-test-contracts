import logging
import sys
from typing import Any, Dict, Optional

from core.utils.errors import ConfigurationError

# Create a logger
logger = logging.getLogger("Audit Agent")

# Set the logging level to DEBUG
logger.setLevel(logging.DEBUG)

# Create a formatter
formatter = logging.Formatter("%(levelname)s: %(asctime)s - %(name)s - %(message)s")

# Create a stream handler (for console output)
try:
    stream_handler = logging.StreamHandler(sys.stdout)
    stream_handler.setFormatter(formatter)
    logger.addHandler(stream_handler)
except Exception as e:
    raise ConfigurationError("Failed to initialize logger", details={"error": str(e)}) from e


def log_with_context(
    level: int, msg: str, extra: Optional[Dict[str, Any]] = None, exc_info: bool = False
) -> None:
    """
    Log a message with additional context.

    Args:
        level: The logging level (e.g., logging.INFO, logging.ERROR)
        msg: The message to log
        extra: Additional context to include in the log
        exc_info: Whether to include exception information
    """
    logger.log(level, msg, extra=extra, exc_info=exc_info)


# Export the logger instance and context-aware logging functions
def error(msg: str, extra: Optional[Dict[str, Any]] = None) -> None:
    log_with_context(logging.ERROR, msg, extra)


def exception(msg: str, extra: Optional[Dict[str, Any]] = None) -> None:
    log_with_context(logging.ERROR, msg, extra, exc_info=True)


def info(msg: str, extra: Optional[Dict[str, Any]] = None) -> None:
    log_with_context(logging.INFO, msg, extra)


def warning(msg: str, extra: Optional[Dict[str, Any]] = None) -> None:
    log_with_context(logging.WARNING, msg, extra)


def debug(msg: str, extra: Optional[Dict[str, Any]] = None) -> None:
    log_with_context(logging.DEBUG, msg, extra)


def critical(msg: str, extra: Optional[Dict[str, Any]] = None) -> None:
    log_with_context(logging.CRITICAL, msg, extra)
