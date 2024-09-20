from datetime import timedelta

import config.settings as settings
from api.v1.models.user import User
from api.v1.services.test_auth_service import create_test_access_token, create_test_user
from common.exceptions import ValidationError
from fastapi import APIRouter
from pydantic import BaseModel

router = APIRouter()

if settings.ENVIRONMENT == "development":

    class UsernameRequest(BaseModel):
        username: str

    @router.post("/test-auth/token")
    async def generate_test_token(request: UsernameRequest):
        username = request.username
        # Create or retrieve the test user
        test_user = await User.find_one(User.username == username)
        if not test_user:
            test_user = await create_test_user(username)

        # Generate a JWT token for the test user
        access_token_expires = timedelta(minutes=60)
        access_token = create_test_access_token(
            data={"sub": str(test_user.id)}, expires_delta=access_token_expires
        )

        # Return the token and user info
        return {
            "access_token": access_token,
            "token_type": "bearer",
            "user": test_user.dict(by_alias=True),
        }

else:

    @router.post("/test-auth/token")
    async def disabled_endpoint():
        raise ValidationError("Endpoint not available in production.")
