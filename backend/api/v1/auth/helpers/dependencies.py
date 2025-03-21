from fastapi import Header, HTTPException, Request, status
from jose import JWTError, jwt

from api.v1.auth.helpers.auth_helpers import blacklist_token, is_token_blacklisted
from api.v1.auth.helpers.token_validator import validate_github_token
from config import settings
from core.db.repositories.user import UserRepository
from core.models.user import User
from core.utils.errors import AuthError, AuthorizationError, TokenError
from core.utils.logger import logger

NOT_AUTHORIZED = "Not authorized"


async def get_current_user(request: Request) -> User:
    """
    Get the current authenticated user.
    This function converts custom errors to FastAPI HTTPExceptions.
    """
    try:
        return await _get_current_user_internal(request)
    except TokenError as e:
        raise HTTPException(status_code=401, detail=e.message)
    except AuthorizationError as e:
        raise HTTPException(status_code=403, detail=e.message)
    except AuthError as e:
        raise HTTPException(status_code=401, detail=e.message)
    except Exception as e:
        logger.error(f"Unexpected auth error: {str(e)}")
        raise HTTPException(status_code=500, detail="Authentication failed")


def get_api_key(x_api_key: str = Header(...)):
    """Check if the API key is valid"""
    try:
        if x_api_key != settings.ADMIN_API_KEY:
            logger.warning(f"Unauthorized access attempt with API key: {x_api_key}")
            raise AuthorizationError(message=NOT_AUTHORIZED)
    except AuthorizationError:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail=NOT_AUTHORIZED,
        )


def get_agentic_api_key(x_api_key: str = Header(...)):
    """Check if the agentic API key is valid"""
    try:
        if x_api_key != settings.AGENTIC_API_KEY:
            logger.warning(f"Unauthorized access attempt with API key: {x_api_key}")
            raise AuthorizationError(message=NOT_AUTHORIZED)
    except AuthorizationError:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail=NOT_AUTHORIZED,
        )


async def _get_current_user_internal(request: Request) -> User:
    """Internal function that raises custom errors"""
    token = request.cookies.get("auth_token")
    if not token:
        raise AuthorizationError(message="No token found")

    try:
        # Check blacklist first
        if await is_token_blacklisted(token):
            raise TokenError(message="Session expired. Please login again")

        # Validate JWT
        payload = jwt.decode(token, settings.SECRET_KEY, algorithms=[settings.ALGORITHM])
        github_id: str = payload.get("sub")
        token_version: int = payload.get("version", 0)

        user = await UserRepository.get_by_github_id(github_id)

        if user is None:
            raise AuthorizationError(message="User not found")

        # Ensure user has token_version field
        await user.ensure_token_version()

        # Verify token version if present in both token and user
        if hasattr(user, "token_version") and token_version != user.token_version:
            await blacklist_token(token)
            raise TokenError(message="Token version mismatch")

        # Verify GitHub token is still valid
        if settings.ENVIRONMENT == "development":
            return user

        try:
            validated_user = await validate_github_token(user)
            return validated_user
        except Exception as e:
            # Increment token version and invalidate all sessions if GitHub token is invalid
            await UserRepository.increment_token_version(user)
            await blacklist_token(token)
            raise TokenError(message="GitHub session expired", details={"error": str(e)}) from e

    except JWTError as e:
        raise TokenError(message="Invalid token", details={"error": str(e)}) from e
    except AuthError:
        raise
    except Exception as e:
        logger.error(f"Auth error: {str(e)}")
        raise AuthError(message="Authentication failed", details={"error": str(e)}) from e
