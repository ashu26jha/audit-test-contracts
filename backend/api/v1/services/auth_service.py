from datetime import datetime, timedelta, timezone
from typing import Optional

from api.v1.models.user import User
from bson import ObjectId
from config import settings
from fastapi import Depends, HTTPException
from fastapi.security import OAuth2PasswordBearer
from jose import JWTError, jwt

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/api/v1/auth/token")


def create_access_token(data: dict, expires_delta: Optional[timedelta] = None):
    to_encode = data.copy()
    if expires_delta:
        expire = datetime.now(timezone.utc) + expires_delta
    else:
        expire = datetime.now(timezone.utc) + timedelta(
            minutes=settings.ACCESS_TOKEN_EXPIRE_MINUTES
        )
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, settings.SECRET_KEY, algorithm=settings.ALGORITHM)
    return encoded_jwt


async def get_current_user(token: str = Depends(oauth2_scheme)):
    try:
        payload = jwt.decode(token, settings.SECRET_KEY, algorithms=[settings.ALGORITHM])
        user_id: str = payload.get("sub")
        user_id_obj = ObjectId(user_id)
    except (JWTError, ValueError) as exc:
        raise HTTPException(status_code=401, detail="Could not validate credentials") from exc
    user = await User.find_one({"_id": user_id_obj})
    if user is None:
        raise HTTPException(status_code=401, detail="User not found")
    return user
