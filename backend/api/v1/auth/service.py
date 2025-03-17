from datetime import datetime, timedelta, timezone
from typing import Optional, Tuple

from fastapi import HTTPException, Request
from fastapi.security import OAuth2PasswordBearer
from jose import JWTError, jwt

from api.v1.auth.helpers.auth_helpers import blacklist_token, verify_oauth_state
from api.v1.auth.helpers.token_validator import get_github_access_token
from api.v1.auth.schema import InternalUserResponse, TestAuthResponse, UserResponse
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

    # Check organization membership and manage subscription
    await is_internal_user(user)

    # Refresh user data to get updated subscription status
    user = await UserRepository.get_by_github_id(user.githubId)

    return access_token, user


async def verify_installation_id(access_token: str, installation_id: str) -> None:
    """
    Verify that the installation ID is valid for the authenticated user.

    Args:
        access_token: GitHub access token
        installation_id: GitHub App installation ID

    Raises:
        HTTPException: If installation ID is invalid
    """
    installations = await github_api_client.get_installations(access_token)
    installation_ids = [str(inst["id"]) for inst in installations]

    if installation_id not in installation_ids:
        raise HTTPException(
            status_code=403,
            detail="Invalid installation ID. The GitHub App is not installed for this user.",
        )


async def is_internal_user(user: User) -> InternalUserResponse:
    """
    Check if the authenticated user is a member of the internal organization
    and manage their subscription accordingly.

    This method:
    - Checks if the user is a member of the specified organization
    - Activates Enterprise subscription if they are a member but don't have it
    - Downgrades to Free if they were Enterprise (without Stripe) but are no longer a member
    - Converts Stripe Enterprise subscriptions to internal Enterprise subscriptions for internal users

    Args:
        user: User object to check for organization membership and manage subscription

    Returns:
        InternalUserResponse with status information:
        - is_internal: Whether user is a member of the organization
        - subscription_activated: Whether Enterprise subscription is currently active
        - subscription_downgraded: Whether subscription was downgraded to Free
    """

    org_name = settings.GITHUB_INTERNAL_ORG
    access_token = user.accessToken

    subscription_activated = False
    subscription_downgraded = False

    if not org_name or not access_token:
        return InternalUserResponse(
            is_internal=False,
            subscription_activated=subscription_activated,
            subscription_downgraded=subscription_downgraded,
        )

    # Check if user is a member of the organization
    is_internal = await github_api_client.is_org_member(access_token, org_name)

    if is_internal:
        # Case 1: User is internal and doesn't have Enterprise subscription - upgrade
        if not user.is_enterprise:
            logger.info(f"Activating Enterprise subscription for internal user {user.username}")
            await UserRepository.activate_internal_subscription(user)
            subscription_activated = True

        # Case 2: User is internal and has Enterprise subscription without Stripe - do nothing
        elif not user.subscription.stripeSubscriptionId:
            subscription_activated = True

        # Case 3: User is internal but has Enterprise subscription through Stripe - convert to internal
        else:  # user.is_enterprise and user.subscription.stripeSubscriptionId must be true here
            logger.info(f"Converting Stripe subscription to internal for user {user.username}")
            # First deactivate the current subscription (this preserves the Stripe customer ID)
            await UserRepository.deactivate_subscription(user)
            # Then activate an internal subscription
            await UserRepository.activate_internal_subscription(user)
            subscription_activated = True
    else:
        # Case 4: User is not internal but has Enterprise subscription without Stripe ID - downgrade
        if user.is_enterprise and not user.subscription.stripeSubscriptionId:
            # Only downgrade users who got Enterprise through org membership (no Stripe subscription)
            logger.info(f"Downgrading non-internal user {user.username} from Enterprise")
            await UserRepository.deactivate_subscription(user)
            subscription_downgraded = True

    return InternalUserResponse(
        is_internal=is_internal,
        subscription_activated=subscription_activated,
        subscription_downgraded=subscription_downgraded,
    )


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
