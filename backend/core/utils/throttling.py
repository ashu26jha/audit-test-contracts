from datetime import datetime, timezone
from functools import wraps
from typing import Optional

from fastapi import HTTPException, Request

from core.models.throttling import ThrottleRecord
from core.utils.logger import logger


def throttle(max_requests: int = 1, use_ip: bool = False):
    """
    Rate limiting decorator that uses MongoDB's TTL for window management.

    Args:
        rate_limit_minutes: Number of minutes in the rate limit window (should match TTL in ThrottleRecord)
        max_requests: Maximum number of requests allowed within the window
        use_ip: Whether to use IP-based (True) or user-based (False) throttling
    """

    def decorator(func):
        @wraps(func)
        async def wrapper(*args, **kwargs):
            try:
                if use_ip:
                    # Get IP from request
                    request: Optional[Request] = None

                    # Look for request in both args and kwargs
                    for arg in args:
                        if isinstance(arg, Request):
                            request = arg
                            break
                    if not request:
                        request = kwargs.get("request")

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

                now = datetime.now(timezone.utc)

                # Get or create throttle record
                record = await ThrottleRecord.find_one({"key": key})

                if record:
                    if record.request_count >= max_requests:
                        raise HTTPException(
                            status_code=429,
                            detail="Rate limit exceeded. Please try again later.",
                        )
                    record.request_count += 1
                    record.last_request = now
                    await record.save()
                else:
                    # Create new record - MongoDB TTL will automatically delete it after the window
                    await ThrottleRecord(
                        key=key,
                        request_count=1,
                        created_at=now,
                        last_request=now,
                    ).insert()

                return await func(*args, **kwargs)
            except HTTPException:
                raise
            except Exception as e:
                logger.error(f"Error in throttling: {str(e)}")
                return await func(*args, **kwargs)

        return wrapper

    return decorator
