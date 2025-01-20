from fastapi import Header, HTTPException, Request, status
from jose import JWTError, jwt

from api.v1.auth.helpers.auth_helpers import blacklist_token, is_token_blacklisted
from api.v1.auth.helpers.token_validator import validate_github_token
from config import settings
from core.db.repositories.user import UserRepository
from core.models.user import User
from core.utils.logger import logger


async def get_current_user(request: Request) -> User:
    token = request.cookies.get("auth_token")
    if not token:
        raise HTTPException(status_code=401, detail="No token found")

    try:
        # Check blacklist first
        if await is_token_blacklisted(token):
            raise HTTPException(status_code=401, detail="Session expired. Please login again")

        # Validate JWT
        payload = jwt.decode(token, settings.SECRET_KEY, algorithms=[settings.ALGORITHM])
        github_id: str = payload.get("sub")
        token_version: int = payload.get("version", 0)

        user = await UserRepository.get_by_github_id(github_id)

        if user is None:
            raise HTTPException(status_code=401, detail="User not found")

        # Ensure user has token_version field
        await user.ensure_token_version()

        # Verify token version if present in both token and user
        if hasattr(user, "token_version") and token_version != user.token_version:
            await blacklist_token(token)
            raise HTTPException(status_code=401, detail="Token version mismatch")

        # Verify GitHub token is still valid
        if settings.ENVIRONMENT == "development":
            return user

        try:
            await validate_github_token(user.accessToken)
        except HTTPException as e:
            # Increment token version and invalidate all sessions if GitHub token is invalid
            await UserRepository.increment_token_version(user)
            await blacklist_token(token)
            raise HTTPException(status_code=401, detail="GitHub session expired") from e

        return user

    except JWTError as e:
        raise HTTPException(status_code=401, detail="Invalid token") from e
    except Exception as e:
        logger.error(f"Auth error: {str(e)}")
        raise HTTPException(status_code=401, detail="Authentication failed") from e


def get_api_key(x_api_key: str = Header(...)):
    if x_api_key != settings.ADMIN_API_KEY:
        logger.warning(f"Unauthorized access attempt with API key: {x_api_key}")
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Not authorized",
        )


def get_agentic_api_key(x_api_key: str = Header(...)):
    if x_api_key != settings.AGENTIC_API_KEY:
        logger.warning(f"Unauthorized access attempt with API key: {x_api_key}")
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Not authorized",
        )
