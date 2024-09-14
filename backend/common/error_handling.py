from __future__ import annotations

from common.logger import logger
from fastapi import HTTPException


def handle_exception(e: Exception):
    logger.error(f"An error occurred: {str(e)}")
    raise HTTPException(status_code=500, detail="Internal server error") from e
