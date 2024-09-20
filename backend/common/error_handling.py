from __future__ import annotations

from common.exceptions import BaseAPIException
from common.logger import logger
from fastapi import HTTPException, Request
from fastapi.responses import JSONResponse


def handle_exception(e: Exception):
    logger.error(f"An error occurred: {str(e)}")
    raise HTTPException(status_code=500, detail="Internal server error") from e


async def global_exception_handler(request: Request, exc: Exception):
    if isinstance(exc, BaseAPIException):
        logger.warning(f"API Exception: {exc.detail}")
        return JSONResponse(status_code=exc.status_code, content={"detail": exc.detail})
    else:
        logger.error(f"Unhandled exception: {str(exc)}", exc_info=True)
        return JSONResponse(status_code=500, content={"detail": "An unexpected error occurred"})
