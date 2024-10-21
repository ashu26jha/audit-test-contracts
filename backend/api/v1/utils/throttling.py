from functools import wraps

import redis
from fastapi import HTTPException

from common import logger
from config import settings

redis_client = redis.from_url(settings.REDIS_URL)


def throttle(rate_limit_minutes: int = 1):
    def decorator(func):
        @wraps(func)
        async def wrapper(*args, **kwargs):
            try:
                # Get the user ID from the current_user dependency
                current_user = kwargs.get("current_user")
                if not current_user:
                    raise HTTPException(status_code=400, detail="User not found")

                user_id = str(current_user.id)
                key = f"throttle:{func.__name__}:{user_id}"

                # Check if the key exists in Redis
                if redis_client.exists(key):
                    raise HTTPException(
                        status_code=429,
                        detail="Rate limit exceeded. Please try again later.",
                    )

                # Set the key with an expiration time
                redis_client.setex(key, rate_limit_minutes * 60, "1")

                return await func(*args, **kwargs)
            except redis.exceptions.ConnectionError as e:
                logger.error(f"Unable to connect to Redis: {str(e)}")
                logger.error(f"Redis URL: {settings.REDIS_URL}")
                logger.warning("Throttling is disabled due to Redis connection error.")
                # Proceed without throttling
                return await func(*args, **kwargs)

        return wrapper

    return decorator
