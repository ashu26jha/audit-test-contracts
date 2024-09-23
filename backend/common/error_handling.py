from api.v1.schemas.api_response_schema import ErrorResponse
from fastapi import HTTPException, Request
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse


async def http_exception_handler(request: Request, exc: HTTPException):
    return JSONResponse(
        status_code=exc.status_code,
        content=ErrorResponse(
            success=False, code=exc.status_code, message=exc.detail, details=None
        ).model_dump(),
    )


async def validation_exception_handler(request: Request, exc: RequestValidationError):
    return JSONResponse(
        status_code=422,
        content=ErrorResponse(
            success=False, code=422, message="Validation error", details=exc.errors()
        ).model_dump(),
    )


async def general_exception_handler(request: Request, exc: Exception):
    return JSONResponse(
        status_code=500,
        content=ErrorResponse(
            success=False, code=500, message="Internal server error", details=str(exc)
        ).model_dump(),
    )
