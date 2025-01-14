from datetime import datetime, timedelta, timezone
from functools import wraps
from typing import Optional

from fastapi import HTTPException, Request

from core.models.throttling import ThrottleRecord
from core.utils.logger import logger


def throttle(rate_limit_minutes: int = 1, max_requests: int = 1, use_ip: bool = False):
    def decorator(func):
        @wraps(func)
        async def wrapper(*args, **kwargs):
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

                now = datetime.now(timezone.utc)
                expires_at = now + timedelta(minutes=rate_limit_minutes)

                # Get or create throttle record
                record = await ThrottleRecord.find_one({"key": key})

                if record:
                    if record.count >= max_requests:
                        raise HTTPException(
                            status_code=429,
                            detail="Rate limit exceeded. Please try again later.",
                        )
                    record.count += 1
                    record.last_request = now
                    await record.save()
                else:
                    await ThrottleRecord(
                        key=key, count=1, last_request=now, expires_at=expires_at
                    ).insert()

                return await func(*args, **kwargs)
            except HTTPException:
                raise
            except Exception as e:
                logger.error(f"Error in throttling: {str(e)}")
                # Proceed without throttling on error
                return await func(*args, **kwargs)

        return wrapper

    return decorator
