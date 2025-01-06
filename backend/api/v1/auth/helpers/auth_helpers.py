import json
import secrets
from datetime import datetime, timezone

from fastapi import HTTPException, Request
from jose import jwt
from redis import Redis
from redis.exceptions import RedisError

from config import settings
from core.utils.logger import logger

redis_client = Redis.from_url(settings.REDIS_URL, decode_responses=True)

# Token related constants
BLACKLIST_PREFIX = "token_blacklist:"

# Security related constants
SUSPICIOUS_IP_PREFIX = "suspicious_ip:"
ATTEMPT_PREFIX = "login_attempt:"
MAX_ATTEMPTS = 5
BLOCK_DURATION = 3600  # 1 hour


# Token functions
async def blacklist_token(token: str) -> None:
    """Add a token to the blacklist with TTL matching the token expiration"""
    try:
        # Decode token to get expiration
        payload = jwt.decode(token, settings.SECRET_KEY, algorithms=[settings.ALGORITHM])
        exp = payload.get("exp")

        if exp:
            now = datetime.now(timezone.utc).timestamp()
            ttl = int(exp - now)

            if ttl > 0:
                redis_client.setex(
                    f"{BLACKLIST_PREFIX}{token}", ttl, json.dumps({"blacklisted_at": now})
                )
    except Exception as e:
        logger.error(f"Error blacklisting token: {str(e)}")
        raise HTTPException(status_code=500, detail="Error processing logout") from e


async def is_token_blacklisted(token: str) -> bool:
    """Check if a token is blacklisted"""
    try:
        return redis_client.exists(f"{BLACKLIST_PREFIX}{token}") == 1
    except RedisError as e:
        logger.error(f"Redis error checking blacklist: {str(e)}")
        return False  # Fail open but with specific error type
    except Exception as e:
        logger.error(f"Unexpected error checking blacklist: {str(e)}")
        return False  # Fail open for other errors


# Security functions
async def track_login_attempt(request: Request) -> None:
    """Track login attempts and block suspicious IPs"""
    ip = _get_client_ip(request)

    if await is_ip_blocked(ip):
        raise HTTPException(
            status_code=429, detail="Too many login attempts. Please try again later."
        )

    key = f"{ATTEMPT_PREFIX}{ip}"
    attempts = redis_client.incr(key)
    if attempts == 1:
        redis_client.expire(key, 60)

    if attempts > MAX_ATTEMPTS:
        await block_ip(ip)
        raise HTTPException(
            status_code=429, detail="Too many login attempts. Please try again later."
        )


async def block_ip(ip: str) -> None:
    """Block an IP address"""
    key = f"{SUSPICIOUS_IP_PREFIX}{ip}"
    redis_client.setex(key, BLOCK_DURATION, "1")


async def is_ip_blocked(ip: str) -> bool:
    """Check if an IP is blocked"""
    return redis_client.exists(f"{SUSPICIOUS_IP_PREFIX}{ip}") == 1


def _get_client_ip(request: Request) -> str:
    """Get client IP from request, handling proxies"""
    forwarded = request.headers.get("X-Forwarded-For")
    return forwarded.split(",")[0].strip() if forwarded else request.client.host


# State management for OAuth
def generate_and_store_oauth_state() -> str:
    """Generate and store OAuth state parameter"""
    state = secrets.token_urlsafe(32)
    redis_client.setex(f"github_state:{state}", 300, "1")  # 5 minute TTL
    return state


def verify_oauth_state(state: str) -> bool:
    """Verify OAuth state parameter"""
    state_key = f"github_state:{state}"
    exists = redis_client.exists(state_key)
    if exists:
        redis_client.delete(state_key)
    return exists == 1
