from fastapi import APIRouter, Depends
from fastapi.responses import JSONResponse, RedirectResponse
from fastapi.security import OAuth2AuthorizationCodeBearer
from starlette.requests import Request

from api.v1.auth.auth_helpers import generate_and_store_oauth_state
from api.v1.models.user import User
from api.v1.schemas.user_schema import UserResponse
from api.v1.services.auth_service import (
    create_access_token,
    get_current_user,
    handle_github_callback,
    handle_logout,
    track_login,
)
from common.throttling import throttle
from config import settings

router = APIRouter()

oauth2_scheme = OAuth2AuthorizationCodeBearer(
    authorizationUrl="https://github.com/login/oauth/authorize",
    tokenUrl="https://github.com/login/oauth/access_token",
)


@router.get("/github-login")
@throttle(rate_limit_minutes=1, max_requests=5, use_ip=True)
async def github_login(request: Request):
    await track_login(request)
    auth_url = f"{settings.GITHUB_APP_URL}&state={generate_and_store_oauth_state()}"
    return RedirectResponse(auth_url)


@router.get("/github-callback")
@throttle(rate_limit_minutes=5, max_requests=10, use_ip=True)
async def github_callback(
    request: Request,
    code: str,
    state: str | None = None,
    installation_id: str | None = None,
    setup_action: str | None = None,
):
    # Handle GitHub callback and get user
    _, user = await handle_github_callback(code, state, installation_id, setup_action)

    # Create our app's JWT token
    jwt_token = create_access_token(data={"sub": str(user.id)}, user=user)

    # Return response with JWT in secure cookie
    response = RedirectResponse(f"{settings.FRONTEND_URL}/login-success")
    response.set_cookie(
        key="auth_token",
        value=jwt_token,
        httponly=True,
        secure=True,
        samesite="strict",
        max_age=settings.ACCESS_TOKEN_EXPIRE_MINUTES * 60,
        path="/",
    )
    return response


@router.post("/logout")
async def logout(request: Request, current_user: User = Depends(get_current_user)):
    await handle_logout(request, current_user)
    response = JSONResponse({"message": "Successfully logged out"})
    response.delete_cookie(
        key="auth_token", path="/", secure=True, httponly=True, samesite="strict"
    )
    return response


@router.get("/me", response_model=UserResponse)
async def read_users_me(current_user: User = Depends(get_current_user)):
    # Convert the model to dict and explicitly convert id to string
    user_dict = current_user.model_dump()
    user_dict["id"] = str(user_dict["id"])  # Convert ObjectId to string

    return UserResponse(**user_dict)
