from typing import Union

from fastapi import APIRouter, Depends, HTTPException, Request
from fastapi.responses import JSONResponse, RedirectResponse
from fastapi.security import OAuth2AuthorizationCodeBearer

from api.v1.auth.helpers.auth_helpers import generate_and_store_oauth_state, track_login_attempt
from api.v1.auth.helpers.dependencies import get_current_user
from api.v1.auth.schema import InternalUserResponse, TestAuthResponse, UsernameRequest, UserResponse
from api.v1.auth.service import (
    create_access_token,
    generate_test_token,
    handle_github_callback,
    handle_logout,
    is_internal_user,
)
from config import settings
from core.models.user import User
from core.schemas.api_response_schema import ErrorResponse, SuccessResponse
from core.utils.errors import (
    AuthError,
    RateLimitError,
    TokenError,
    ValidationError,
)
from core.utils.logger import logger
from core.utils.throttling import throttle

router = APIRouter(prefix="/auth", tags=["auth"])


oauth2_scheme = OAuth2AuthorizationCodeBearer(
    authorizationUrl="https://github.com/login/oauth/authorize",
    tokenUrl="https://github.com/login/oauth/access_token",
)


@router.get("/github-login")
@throttle(max_requests=20, use_ip=True)
async def github_login(request: Request):
    """
    Redirect the user to the GitHub OAuth authorization page.
    """
    try:
        await track_login_attempt(request)
        auth_url = f"{settings.GITHUB_APP_URL}&state={await generate_and_store_oauth_state()}"
        return RedirectResponse(auth_url)
    except RateLimitError as e:
        raise HTTPException(status_code=429, detail=e.message)
    except Exception as e:
        logger.error(f"Error during GitHub login: {str(e)}")
        raise HTTPException(status_code=500, detail="Failed to initiate GitHub login")


@router.get("/github-callback")
@throttle(max_requests=20, use_ip=True)
async def github_callback(
    request: Request,
    code: str,
    state: str | None = None,
    installation_id: str | None = None,
    setup_action: str | None = None,
):
    """
    Handle the GitHub OAuth callback.
    """
    try:
        _, user = await handle_github_callback(code, state, installation_id, setup_action)

        # Create our app's JWT token
        jwt_token = create_access_token(data={"sub": user.githubId}, user=user)

        # Return response with JWT in secure cookie
        response = RedirectResponse(f"{settings.FRONTEND_URL}/login-success")
        response.set_cookie(
            key="auth_token",
            value=jwt_token,
            domain=settings.COOKIE_DOMAIN,
            httponly=True,
            secure=settings.ENVIRONMENT == "production",
            samesite="strict",
            max_age=settings.ACCESS_TOKEN_EXPIRE_MINUTES * 60,  # 1 week (same as JWT token)
            path="/",
        )
        return response
    except ValidationError as e:
        raise HTTPException(status_code=400, detail=e.message)
    except TokenError as e:
        raise HTTPException(status_code=401, detail=e.message)
    except AuthError as e:
        raise HTTPException(status_code=403, detail=e.message)
    except Exception as e:
        logger.error(f"GitHub callback error: {str(e)}")
        raise HTTPException(status_code=500, detail="Failed to authenticate with GitHub")


@router.get("/me", response_model=Union[SuccessResponse[UserResponse], ErrorResponse])
async def get_current_user_info(current_user: User = Depends(get_current_user)):
    """Get current user information."""
    return SuccessResponse(data=UserResponse.model_validate(current_user))


@router.get(
    "/check-internal-status",
    response_model=Union[SuccessResponse[InternalUserResponse], ErrorResponse],
)
async def check_internal_status(current_user: User = Depends(get_current_user)):
    """
    Check if the current user is a member of the internal organization and
    manage their subscription accordingly:
    - Activate Enterprise subscription if they are a member
    - Downgrade to Free if they were Enterprise but are no longer a member

    This endpoint is meant to be called by the frontend after GitHub App installation
    and before initiating scans.
    """
    try:
        result = await is_internal_user(current_user)
        return SuccessResponse(data=result)
    except AuthError as e:
        raise HTTPException(status_code=403, detail=e.message)
    except Exception as e:
        logger.error(f"Error checking internal status: {str(e)}")
        raise HTTPException(status_code=500, detail="Failed to check organization membership")


@router.post("/logout")
async def logout(request: Request):
    """
    Log out the current user.
    """
    try:
        await handle_logout(request)
        response = JSONResponse(
            content=SuccessResponse(data={"message": "Successfully logged out"}).model_dump()
        )
        response.delete_cookie(
            key="auth_token", path="/", secure=True, httponly=True, samesite="strict"
        )
        return response
    except Exception as e:
        # We allow logout to fail silently for user experience
        logger.error(f"Error during logout: {str(e)}")
        response = JSONResponse(
            content=SuccessResponse(data={"message": "Successfully logged out"}).model_dump()
        )
        response.delete_cookie(
            key="auth_token", path="/", secure=True, httponly=True, samesite="strict"
        )
        return response


@router.post(
    "/test-auth/token", response_model=Union[SuccessResponse[TestAuthResponse], ErrorResponse]
)
async def test_auth(request: UsernameRequest):
    """Test authentication endpoint using basic auth."""
    if settings.ENVIRONMENT == "development":
        try:
            test_user = await generate_test_token(request.username)
            return SuccessResponse(data=test_user)
        except Exception as e:
            logger.error(f"Error generating test token: {str(e)}")
            raise HTTPException(status_code=500, detail="Failed to generate test token")

    raise HTTPException(status_code=404, detail="Not Found")
