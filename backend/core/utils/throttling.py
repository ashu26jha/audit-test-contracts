from functools import wraps
from typing import Optional

from fastapi import HTTPException, Request

from config.redis_client import REDIS_CLIENT
from core.utils.logger import logger


def throttle(rate_limit_minutes: int = 1, max_requests: int = 1, use_ip: bool = False):
    def decorator(func):
        @wraps(func)
        async def wrapper(*args, **kwargs):
            # If Redis is not available, skip throttling
            if not REDIS_CLIENT:
                logger.warning("Redis unavailable, throttling disabled")
                return await func(*args, **kwargs)

            try:
                if use_ip:
                    # Get IP from request
                    request: Optional[Request] = kwargs.get("request")
                    if not request:
                        logger.error("Request object not found for IP-based throttling")
                        return await func(*args, **kwargs)

                    # Get client IP, handling proxies
                    forwarded = request.headers.get("X-Forwarded-For")
                    client_ip = (
                        forwarded.split(",")[0].strip() if forwarded else request.client.host
                    )
                    key = f"throttle:{func.__name__}:{client_ip}"
                else:
                    # User-based throttling
                    current_user = kwargs.get("current_user")
                    if not current_user:
                        raise HTTPException(status_code=400, detail="User not found")
                    key = f"throttle:{func.__name__}:{current_user.id}"

                # Get current request count
                current_count = REDIS_CLIENT.get(key)
                if current_count and int(current_count) >= max_requests:
                    raise HTTPException(
                        status_code=429,
                        detail="Rate limit exceeded. Please try again later.",
                    )

                # Increment counter or set initial value
                if current_count:
                    REDIS_CLIENT.incr(key)
                else:
                    REDIS_CLIENT.setex(key, rate_limit_minutes * 60, "1")

                return await func(*args, **kwargs)
            except Exception as e:
                logger.error(f"Error in throttling: {str(e)}")
                # Proceed without throttling on error
                return await func(*args, **kwargs)

        return wrapper

    return decorator
