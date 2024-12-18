from datetime import datetime, timedelta, timezone
from typing import Optional, Tuple

import httpx
from bson import ObjectId
from fastapi import Header, HTTPException, Request, status
from fastapi.security import OAuth2PasswordBearer
from jose import JWTError, jwt

from api.v1.auth.auth_helpers import (
    blacklist_token,
    increment_token_version,
    is_token_blacklisted,
    track_login_attempt,
    verify_oauth_state,
)
from api.v1.models.user import User
from api.v1.services.github_service import GitHubService
from common import logger
from config import settings

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/api/v1/auth/token")
github_service = GitHubService()


def create_access_token(data: dict, user: User, expires_delta: Optional[timedelta] = None):
    to_encode = data.copy()
    to_encode.update({"version": user.token_version})

    if expires_delta:
        expire = datetime.now(timezone.utc) + expires_delta
    else:
        expire = datetime.now(timezone.utc) + timedelta(
            minutes=settings.ACCESS_TOKEN_EXPIRE_MINUTES
        )
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, settings.SECRET_KEY, algorithm=settings.ALGORITHM)
    return encoded_jwt


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
        user_id: str = payload.get("sub")
        token_version: int = payload.get("version", 0)

        user_id_obj = ObjectId(user_id)
        user = await User.find_one({"_id": user_id_obj})

        if user is None:
            raise HTTPException(status_code=401, detail="User not found")

        # Ensure user has token_version field
        await user.ensure_token_version()

        # Verify token version if present in both token and user
        if hasattr(user, "token_version") and token_version != user.token_version:
            await blacklist_token(token)
            raise HTTPException(status_code=401, detail="Token version mismatch")

        # Verify GitHub token is still valid
        try:
            await github_service.get_user_data(user.accessToken)
        except HTTPException:
            # Increment token version and invalidate all sessions if GitHub token is invalid
            await increment_token_version(user)
            await blacklist_token(token)
            raise HTTPException(status_code=401, detail="GitHub session expired")

        return user

    except JWTError:
        raise HTTPException(status_code=401, detail="Invalid token")
    except Exception as e:
        logger.error(f"Auth error: {str(e)}")
        raise HTTPException(status_code=401, detail="Authentication failed")


async def handle_user_data(user_data: dict, access_token: str) -> User:
    """Create or update a user based on GitHub data"""
    # Check if user exists
    user = await User.by_github_id(str(user_data["id"]))

    # Get installations
    installations = await github_service.github_helpers.get_installations(access_token)
    installation_ids = [inst["id"] for inst in installations]

    if not user:
        # Create new user
        user = User(
            githubId=str(user_data["id"]),
            username=user_data["login"],
            email=user_data["email"],
            accessToken=access_token,
            avatarUrl=user_data["avatar_url"],
            name=user_data["name"],
            installationId=installation_ids,
            token_version=0,
        )
        await user.create()
    else:
        # Ensure user has token_version field
        await user.ensure_token_version()

        # Update existing user and increment token version if token changed
        should_increment = False

        # Check if token has changed
        if user.accessToken != access_token:
            should_increment = True

        # Check if current GitHub token is still valid
        try:
            await github_service.get_user_data(user.accessToken)
        except Exception:
            should_increment = True

        if should_increment:
            await increment_token_version(user)

        await user.update(
            {
                "$set": {
                    "accessToken": access_token,
                    "installationId": installation_ids,
                    "avatarUrl": user_data["avatar_url"],
                    "name": user_data["name"],
                    "email": user_data["email"],
                }
            }
        )
        # Refresh user object after update
        user = await User.by_github_id(str(user_data["id"]))

    return user


async def handle_github_callback(
    code: str,
    state: Optional[str] = None,
    installation_id: Optional[str] = None,
    setup_action: Optional[str] = None,
) -> Tuple[str, User]:
    """Handle GitHub OAuth callback and return access token and user"""
    # Validate the callback parameters
    if installation_id is not None:
        if setup_action not in ["install", "update"]:
            raise HTTPException(status_code=400, detail="Invalid setup_action parameter")
    elif state and not verify_oauth_state(state):
        raise HTTPException(status_code=400, detail="Invalid state parameter")
    elif not state and not installation_id:
        raise HTTPException(status_code=400, detail="State parameter required for OAuth flow")

    # Exchange code for access token
    access_token = await exchange_github_code(code, state)

    # If this is a GitHub App callback, verify installation
    if installation_id is not None:
        await verify_installation_id(access_token, installation_id)

    # Get user data and create/update user
    user_data = await github_service.get_user_data(access_token)
    user = await handle_user_data(user_data, access_token)

    return access_token, user


async def exchange_github_code(code: str, state: Optional[str] = None) -> str:
    """Exchange GitHub code for access token"""
    token_url = "https://github.com/login/oauth/access_token"
    data = {
        "client_id": settings.GITHUB_CLIENT_ID,
        "client_secret": settings.GITHUB_CLIENT_SECRET,
        "code": code,
    }
    if state:
        data["state"] = state

    async with httpx.AsyncClient() as client:
        response = await client.post(
            token_url,
            headers={"Accept": "application/json"},
            data=data,
        )

        if response.status_code != 200:
            raise HTTPException(status_code=400, detail="Failed to authenticate with GitHub")

        token_data = response.json()
        if "error" in token_data:
            raise HTTPException(status_code=400, detail=token_data.get("error_description"))

        access_token = token_data.get("access_token")
        if not access_token:
            raise HTTPException(status_code=400, detail="Invalid token response")

        return access_token


async def verify_installation_id(access_token: str, installation_id: str) -> None:
    """Verify that the installation_id is valid for the user"""
    installations = await github_service.github_helpers.get_installations(access_token)
    installation_ids = [str(inst["id"]) for inst in installations]

    if installation_id not in installation_ids:
        raise HTTPException(status_code=403, detail="Invalid installation_id")


async def handle_logout(request: Request) -> None:
    """Handle user logout"""
    token = request.cookies.get("auth_token")
    if token:
        try:
            await blacklist_token(token)

            # Try to get user from token
            try:
                # Decode token
                payload = jwt.decode(token, settings.SECRET_KEY, algorithms=[settings.ALGORITHM])
                user_id = payload.get("sub")
                if user_id:
                    # Get user from database
                    user = await User.get(ObjectId(user_id))
                    if user:
                        # Increment token version
                        await increment_token_version(user)
            except (JWTError, ValueError):
                # If token is invalid or user not found, just log it
                logger.warning("Invalid token during logout")

        except Exception as e:
            logger.error(f"Error during logout: {str(e)}")


async def track_login(request: Request) -> None:
    """Track login attempts and handle security"""
    await track_login_attempt(request)


def get_api_key(x_api_key: str = Header(...)):
    if x_api_key != settings.ADMIN_API_KEY:
        logger.warning(f"Unauthorized access attempt with API key: {x_api_key}")
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Not authorized",
        )
