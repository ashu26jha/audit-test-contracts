from datetime import datetime, timedelta, timezone
from typing import Optional, Tuple

from fastapi import HTTPException, Request
from fastapi.security import OAuth2PasswordBearer
from jose import JWTError, jwt

from api.v1.auth.helpers.auth_helpers import blacklist_token, verify_oauth_state
from api.v1.auth.helpers.token_validator import get_github_access_token
from api.v1.auth.schema import TestAuthResponse, UserResponse
from api.v1.github.helpers.github_api_client import GitHubAPIClient
from api.v1.github.service import GitHubService
from config import settings
from core.db.repositories.user import UserRepository
from core.models.user import User
from core.utils.logger import logger

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/api/v1/auth/token")
github_service = GitHubService()
github_api_client = GitHubAPIClient()


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


async def handle_user_data(user_data: dict, access_token: str, refresh_token: str) -> User:
    """Create or update a user based on GitHub data"""
    # Check if user exists
    user = await UserRepository.get_by_github_id(str(user_data["id"]))

    # Get installations
    installations = await github_api_client.get_installations(access_token)
    installation_ids = [inst["id"] for inst in installations]

    if not user:
        # Create new user
        user = await UserRepository.create_user(
            github_id=str(user_data["id"]),
            username=user_data["login"],
            email=user_data["email"],
            access_token=access_token,
            refresh_token=refresh_token,
            avatar_url=user_data["avatar_url"],
            name=user_data["name"],
            installation_ids=installation_ids,
        )
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
            await UserRepository.increment_token_version(user)

        user = await UserRepository.update_user(
            user=user,
            access_token=access_token,
            refresh_token=refresh_token,
            installation_ids=installation_ids,
            avatar_url=user_data["avatar_url"],
            name=user_data["name"],
            email=user_data["email"],
        )

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
    elif state and not await verify_oauth_state(state):
        raise HTTPException(status_code=400, detail="Invalid state parameter")
    elif not state and not installation_id:
        raise HTTPException(status_code=400, detail="State parameter required for OAuth flow")

    # Exchange code for access token
    data = {
        "client_id": settings.GITHUB_CLIENT_ID,
        "client_secret": settings.GITHUB_CLIENT_SECRET,
        "code": code,
    }
    access_token, refresh_token = await get_github_access_token(data)

    # If this is a GitHub App callback, verify installation
    if installation_id is not None:
        await verify_installation_id(access_token, installation_id)

    # Get user data and create/update user
    user_data = await github_service.get_user_data(access_token)
    user = await handle_user_data(user_data, access_token, refresh_token)

    return access_token, user


async def verify_installation_id(access_token: str, installation_id: str) -> None:
    """Verify that the installation_id is valid for the user"""
    installations = await github_api_client.get_installations(access_token)
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
                github_id = payload.get("sub")
                if github_id:
                    # Get user from database
                    user = await UserRepository.get_by_github_id(github_id)
                    if user:
                        # Increment token version
                        await UserRepository.increment_token_version(user)
            except JWTError:
                # If token is invalid or user not found, just log it
                logger.warning("Invalid token during logout")

        except Exception as e:
            logger.error(f"Error during logout: {str(e)}")


async def generate_test_token(username: str):
    # Create or retrieve the test user
    test_user = await UserRepository.get_by_username(username)
    if not test_user:
        test_user = await UserRepository.create_test_user(username)

    user_response = UserResponse.model_validate(test_user)

    # Generate a JWT token for the test user
    access_token_expires = timedelta(minutes=settings.ACCESS_TOKEN_EXPIRE_MINUTES)
    access_token = create_access_token(
        data={"sub": user_response.githubId},
        user=test_user,
        expires_delta=access_token_expires,
    )

    return TestAuthResponse(
        access_token=access_token,
        token_type="bearer",
        user=user_response.model_dump(),
    )
