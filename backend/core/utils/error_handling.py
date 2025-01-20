from fastapi import HTTPException, Request
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse

from core.schemas.api_response_schema import ErrorResponse


async def http_exception_handler(_: Request, exc: HTTPException):
    return JSONResponse(
        status_code=exc.status_code,
        content=ErrorResponse(
            success=False, code=exc.status_code, message=exc.detail, details=None
        ).model_dump(),
    )


async def validation_exception_handler(_: Request, exc: RequestValidationError):
    # Extract only JSON-serializable data from the errors
    processed_errors = []
    for error in exc.errors():
        error_dict = {
            "type": error.get("type"),
            "loc": error.get("loc"),
            "msg": error.get("msg"),
            "input": error.get("input"),
        }
        # Handle ctx specially to avoid non-serializable objects
        if "ctx" in error:
            ctx = error["ctx"]
            if isinstance(ctx, dict):
                error_dict["ctx"] = {
                    k: str(v) if not isinstance(v, (str, int, float, bool, type(None))) else v
                    for k, v in ctx.items()
                }

        processed_errors.append(error_dict)

    return JSONResponse(
        status_code=422,
        content=ErrorResponse(
            success=False, code=422, message="Validation error", details=processed_errors
        ).model_dump(),
    )


async def general_exception_handler(_: Request, exc: Exception):
    return JSONResponse(
        status_code=500,
        content=ErrorResponse(
            success=False, code=500, message="Internal server error", details=str(exc)
        ).model_dump(),
    )
