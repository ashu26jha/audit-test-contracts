import functools
from typing import Callable, TypeVar

from fastapi import HTTPException, status

from core.utils.errors import (
    AuthError,
    AuthorizationError,
    BranchError,
    CloneError,
    ConfigurationError,
    ConnectionError,
    ContractError,
    CreditError,
    CriticError,
    DatabaseError,
    DependencyError,
    DetectorError,
    EnvironmentError,
    HTTPClientError,
    InitializationError,
    LLMError,
    ModelError,
    PaymentError,
    PromptError,
    QueryError,
    RateLimitError,
    RepositoryError,
    ScanError,
    SubscriptionError,
    TokenError,
    ToolError,
)
from core.utils.logger import logger

T = TypeVar("T", bound=Callable)


def handle_domain_errors(scan_type: str) -> Callable[[T], T]:
    """
    Decorator to standardize error handling for scanner-related routes.
    Catches domain-specific errors and converts them to appropriate HTTP exceptions
    based on the same mapping used in error_handling.py.

    Args:
        scan_type: String indicating the type of scan (for logging purposes)

    Returns:
        A decorator function that wraps the route handler
    """

    def decorator(func: T) -> T:
        @functools.wraps(func)
        async def wrapper(*args, **kwargs):
            try:
                return await func(*args, **kwargs)

            # Most specific exceptions first
            # Authentication-related exceptions
            except TokenError as e:
                logger.error(f"Token error in {scan_type} scan: {str(e)}")
                raise HTTPException(
                    status_code=status.HTTP_401_UNAUTHORIZED,
                    detail=str(e),
                )

            # Payment-related exceptions - specific first
            except CreditError as e:
                logger.error(f"Credit error in {scan_type} scan: {str(e)}")
                raise HTTPException(
                    status_code=status.HTTP_402_PAYMENT_REQUIRED,
                    detail=str(e),
                )
            except SubscriptionError as e:
                logger.error(f"Subscription error in {scan_type} scan: {str(e)}")
                raise HTTPException(
                    status_code=status.HTTP_403_FORBIDDEN,
                    detail=str(e),
                )
            except PaymentError as e:
                logger.error(f"Payment error in {scan_type} scan: {str(e)}")
                raise HTTPException(
                    status_code=status.HTTP_402_PAYMENT_REQUIRED,
                    detail=str(e),
                )

            # Repository-related exceptions - specific first
            except CloneError as e:
                logger.error(f"Clone error in {scan_type} scan: {str(e)}")
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    detail=str(e),
                )
            except BranchError as e:
                logger.error(f"Branch error in {scan_type} scan: {str(e)}")
                raise HTTPException(
                    status_code=status.HTTP_404_NOT_FOUND,
                    detail=str(e),
                )
            except ContractError as e:
                logger.error(f"Contract error in {scan_type} scan: {str(e)}")
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    detail=str(e),
                )
            except RepositoryError as e:
                logger.error(f"Repository error in {scan_type} scan: {str(e)}")
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    detail=str(e),
                )

            # Scan-related exceptions - specific first
            except InitializationError as e:
                logger.error(f"Initialization error in {scan_type} scan: {str(e)}")
                raise HTTPException(
                    status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                    detail=str(e),
                )
            except DetectorError as e:
                logger.error(f"Detector error in {scan_type} scan: {str(e)}")
                raise HTTPException(
                    status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                    detail=str(e),
                )
            except CriticError as e:
                logger.error(f"Critic error in {scan_type} scan: {str(e)}")
                raise HTTPException(
                    status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                    detail=str(e),
                )
            except ScanError as e:
                logger.error(f"Scan error in {scan_type} scan: {str(e)}")
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    detail=str(e),
                )

            # LLM-related exceptions
            except ModelError as e:
                logger.error(f"Model error in {scan_type} scan: {str(e)}")
                raise HTTPException(
                    status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                    detail=str(e),
                )
            except PromptError as e:
                logger.error(f"Prompt error in {scan_type} scan: {str(e)}")
                raise HTTPException(
                    status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                    detail=str(e),
                )
            except LLMError as e:
                logger.error(f"LLM error in {scan_type} scan: {str(e)}")
                raise HTTPException(
                    status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                    detail=str(e),
                )

            # Database-related exceptions
            except ConnectionError as e:
                logger.error(f"Connection error in {scan_type} scan: {str(e)}")
                raise HTTPException(
                    status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                    detail=str(e),
                )
            except QueryError as e:
                logger.error(f"Query error in {scan_type} scan: {str(e)}")
                raise HTTPException(
                    status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                    detail=str(e),
                )
            except DatabaseError as e:
                logger.error(f"Database error in {scan_type} scan: {str(e)}")
                raise HTTPException(
                    status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                    detail=str(e),
                )

            # Environment-related exceptions
            except ConfigurationError as e:
                logger.error(f"Configuration error in {scan_type} scan: {str(e)}")
                raise HTTPException(
                    status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                    detail=str(e),
                )
            except DependencyError as e:
                logger.error(f"Dependency error in {scan_type} scan: {str(e)}")
                raise HTTPException(
                    status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                    detail=str(e),
                )
            except EnvironmentError as e:
                logger.error(f"Environment error in {scan_type} scan: {str(e)}")
                raise HTTPException(
                    status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                    detail=str(e),
                )

            # Other specific exceptions
            except AuthorizationError as e:
                logger.error(f"Authorization error in {scan_type} scan: {str(e)}")
                raise HTTPException(
                    status_code=status.HTTP_403_FORBIDDEN,
                    detail=str(e),
                )
            except AuthError as e:
                logger.error(f"Auth error in {scan_type} scan: {str(e)}")
                raise HTTPException(
                    status_code=status.HTTP_401_UNAUTHORIZED,
                    detail=str(e),
                )
            except RateLimitError as e:
                logger.error(f"Rate limit error in {scan_type} scan: {str(e)}")
                raise HTTPException(
                    status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                    detail=str(e),
                )
            except HTTPClientError as e:
                logger.error(f"HTTP client error in {scan_type} scan: {str(e)}")
                raise HTTPException(
                    status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                    detail=str(e),
                )
            except ToolError as e:
                logger.error(f"Tool error in {scan_type} scan: {str(e)}")
                raise HTTPException(
                    status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                    detail=str(e),
                )

            # Catch-all for any other exceptions
            except Exception as e:
                logger.error(f"Unexpected error in {scan_type} scan: {str(e)}")
                raise HTTPException(
                    status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                    detail="An unexpected error occurred during scan initialization",
                )

        return wrapper

    return decorator
