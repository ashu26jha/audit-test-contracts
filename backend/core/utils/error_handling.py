from typing import Dict, Type

from fastapi import HTTPException, Request
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse

from config import settings
from core.schemas.api_response_schema import ErrorResponse
from core.utils.errors import (
    AuditAgentError,
    AuthError,
    BranchError,
    ContractError,
    CreditError,
    DatabaseError,
    DetectorError,
    EnvironmentError,
    HTTPClientError,
    InitializationError,
    LLMError,
    PaymentError,
    RateLimitError,
    RepositoryError,
    ScanError,
    SubscriptionError,
    TokenError,
    ValidationError,
)
from core.utils.logger import logger

# Map exception types to HTTP status codes
ERROR_STATUS_CODES: Dict[Type[AuditAgentError], int] = {
    # Auth errors -> 401, 403
    AuthError: 401,
    TokenError: 401,
    PermissionError: 403,
    # Validation errors -> 400, 422
    ValidationError: 422,
    RepositoryError: 400,
    ContractError: 400,
    # Scan errors -> 400, 500
    ScanError: 400,  # Base scan errors are client errors by default
    InitializationError: 500,  # Initialization failures are server errors
    DetectorError: 500,  # Detector failures are server errors
    # Payment/subscription errors -> 402, 403
    PaymentError: 402,
    CreditError: 402,
    SubscriptionError: 403,
    # Resource errors -> 404
    BranchError: 404,
    # Rate limiting -> 429
    RateLimitError: 429,
    # Service errors -> 500, 503
    DatabaseError: 503,
    LLMError: 503,
    EnvironmentError: 500,
    HTTPClientError: 503,  # External service errors -> 503 Service Unavailable
    # Default for AuditAgentError -> 500
    AuditAgentError: 500,
}


async def audit_agent_exception_handler(request: Request, exc: AuditAgentError) -> JSONResponse:
    """Handle all custom AuditAgentError exceptions."""
    # Get the most specific status code for this exception type
    status_code = 500
    for error_type, code in ERROR_STATUS_CODES.items():
        if isinstance(exc, error_type):
            status_code = code
            break

    # Log the error with appropriate severity based on status code
    if status_code >= 500:
        logger.error(
            f"Server error: {exc.message}",
            extra={"details": exc.details, "status_code": status_code},
        )
    else:
        logger.warning(
            f"Client error: {exc.message}",
            extra={"details": exc.details, "status_code": status_code},
        )

    return JSONResponse(
        status_code=status_code,
        content=ErrorResponse(
            success=False, code=status_code, message=exc.message, details=exc.details
        ).model_dump(),
    )


async def http_exception_handler(request: Request, exc: HTTPException) -> JSONResponse:
    """Handle FastAPI HTTPException."""
    return JSONResponse(
        status_code=exc.status_code,
        content=ErrorResponse(
            success=False, code=exc.status_code, message=exc.detail, details=None
        ).model_dump(),
    )


async def validation_exception_handler(
    request: Request, exc: RequestValidationError
) -> JSONResponse:
    """Handle FastAPI RequestValidationError."""
    errors = []
    for error in exc.errors():
        error_dict = dict(error)
        # Handle ValueError in ctx
        if "ctx" in error_dict and "error" in error_dict["ctx"]:
            if isinstance(error_dict["ctx"]["error"], ValueError):
                error_dict["ctx"]["error"] = str(error_dict["ctx"]["error"])
        errors.append(error_dict)

    return JSONResponse(
        status_code=422,
        content=ErrorResponse(
            success=False, code=422, message="Validation error", details=errors
        ).model_dump(),
    )


# Remove details in production to prevent leaking info
async def general_exception_handler(request: Request, exc: Exception):
    """Handle any unhandled exceptions."""
    # Log unexpected exceptions
    logger.exception("Unhandled exception occurred", exc_info=exc)

    return JSONResponse(
        status_code=500,
        content=ErrorResponse(
            success=False,
            code=500,
            message="Internal server error",
            details=str(exc) if settings.ENVIRONMENT == "development" else None,
        ).model_dump(),
    )
