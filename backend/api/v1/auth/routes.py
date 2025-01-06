from typing import Union

from fastapi import APIRouter, Depends, HTTPException, Request
from fastapi.responses import JSONResponse, RedirectResponse
from fastapi.security import OAuth2AuthorizationCodeBearer

from api.v1.auth.helpers.auth_helpers import generate_and_store_oauth_state, track_login_attempt
from api.v1.auth.helpers.dependencies import get_current_user
from api.v1.auth.schema import TestAuthResponse, UsernameRequest, UserResponse
from api.v1.auth.service import (
    create_access_token,
    generate_test_token,
    handle_github_callback,
    handle_logout,
)
from config import settings
from core.models.user import User
from core.schemas.api_response_schema import ErrorResponse, SuccessResponse
from core.utils.throttling import throttle

router = APIRouter(prefix="/auth", tags=["auth"])


oauth2_scheme = OAuth2AuthorizationCodeBearer(
    authorizationUrl="https://github.com/login/oauth/authorize",
    tokenUrl="https://github.com/login/oauth/access_token",
)


@router.get("/github-login")
@throttle(rate_limit_minutes=1, max_requests=5, use_ip=True)
async def github_login(request: Request):
    """
    Redirect the user to the GitHub OAuth authorization page.
    """
    await track_login_attempt(request)
    auth_url = f"{settings.GITHUB_APP_URL}&state={generate_and_store_oauth_state()}"
    return RedirectResponse(auth_url)


@router.get("/github-callback")
@throttle(rate_limit_minutes=5, max_requests=10, use_ip=True)
async def github_callback(
    _: Request,
    code: str,
    state: str | None = None,
    installation_id: str | None = None,
    setup_action: str | None = None,
):
    """
    Handle the GitHub OAuth callback.
    """
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
        secure=True,
        samesite="strict",
        max_age=settings.ACCESS_TOKEN_EXPIRE_MINUTES * 60,
        path="/",
    )
    return response


@router.get("/me", response_model=Union[SuccessResponse[UserResponse], ErrorResponse])
async def read_users_me(current_user: User = Depends(get_current_user)):
    """
    Get the current user's information.
    """
    return SuccessResponse(data=UserResponse.model_validate(current_user))


@router.post("/logout")
async def logout(request: Request):
    """
    Log out the current user.
    """
    await handle_logout(request)
    response = JSONResponse(
        content=SuccessResponse(data={"message": "Successfully logged out"}).model_dump()
    )
    response.delete_cookie(
        key="auth_token", path="/", secure=True, httponly=True, samesite="strict"
    )
    return response


@router.get(
    "/test-auth/token", response_model=Union[SuccessResponse[TestAuthResponse], ErrorResponse]
)
async def test_auth(request: UsernameRequest):
    """Test authentication endpoint using basic auth."""
    if settings.ENVIRONMENT == "development":
        test_user = await generate_test_token(request.username)
        return SuccessResponse(data=test_user)

    raise HTTPException(status_code=404, detail="Not Found")
