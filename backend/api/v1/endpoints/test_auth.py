from datetime import timedelta

from fastapi import APIRouter, HTTPException, status
from pydantic import BaseModel

from api.v1.models.user import User
from api.v1.schemas.api_response_schema import ErrorResponse, SuccessResponse
from api.v1.schemas.user_schema import UserResponse
from api.v1.services.auth_service import create_access_token
from api.v1.services.test_auth_service import create_test_user
from config import settings

router = APIRouter()

if settings.ENVIRONMENT == "development":

    class UsernameRequest(BaseModel):
        username: str

    @router.post(
        "/test-auth/token",
        response_model=SuccessResponse,
        status_code=status.HTTP_201_CREATED,
    )
    async def generate_test_token(request: UsernameRequest):
        username = request.username
        # Create or retrieve the test user
        test_user = await User.find_one(User.username == username)
        if not test_user:
            user_response = await create_test_user(username)
        else:
            user_response = UserResponse.model_validate(test_user)

        # Generate a JWT token for the test user
        access_token_expires = timedelta(minutes=settings.ACCESS_TOKEN_EXPIRE_MINUTES)
        access_token = create_access_token(
            data={"sub": user_response.githubId},
            user=test_user if test_user else await User.by_github_id(user_response.githubId),
            expires_delta=access_token_expires,
        )

        return SuccessResponse(
            data={
                "access_token": access_token,
                "token_type": "bearer",
                "user": user_response.model_dump(),
            }
        )

else:

    @router.post("/test-auth/token", response_model=ErrorResponse)
    async def disabled_endpoint():
        raise HTTPException(status_code=404, detail="Not Found")
