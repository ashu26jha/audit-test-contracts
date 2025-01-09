import json
import secrets
from datetime import datetime, timezone

from fastapi import HTTPException, Request
from jose import jwt

from config import settings
from config.redis_client import REDIS_CLIENT
from core.utils.logger import logger

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
    if not REDIS_CLIENT:
        logger.warning("Redis unavailable, token blacklisting disabled")
        return

    try:
        # Decode token to get expiration
        payload = jwt.decode(token, settings.SECRET_KEY, algorithms=[settings.ALGORITHM])
        exp = payload.get("exp")

        if exp:
            now = datetime.now(timezone.utc).timestamp()
            ttl = int(exp - now)

            if ttl > 0:
                REDIS_CLIENT.setex(
                    f"{BLACKLIST_PREFIX}{token}", ttl, json.dumps({"blacklisted_at": now})
                )
    except Exception as e:
        logger.error(f"Error blacklisting token: {str(e)}")
        raise HTTPException(status_code=500, detail="Error processing logout") from e


async def is_token_blacklisted(token: str) -> bool:
    """Check if a token is blacklisted"""
    if not REDIS_CLIENT:
        logger.warning("Redis unavailable, token blacklist check disabled")
        return False

    try:
        return REDIS_CLIENT.exists(f"{BLACKLIST_PREFIX}{token}") == 1
    except Exception as e:
        logger.error(f"Error checking blacklist: {str(e)}")
        return False


# Security functions
async def track_login_attempt(request: Request) -> None:
    """Track login attempts and block suspicious IPs"""
    if not REDIS_CLIENT:
        logger.warning("Redis unavailable, login attempt tracking disabled")
        return

    ip = _get_client_ip(request)
    if await is_ip_blocked(ip):
        raise HTTPException(
            status_code=429, detail="Too many login attempts. Please try again later."
        )

    key = f"{ATTEMPT_PREFIX}{ip}"
    attempts = REDIS_CLIENT.incr(key)
    if attempts == 1:
        REDIS_CLIENT.expire(key, 60)

    if attempts > MAX_ATTEMPTS:
        await block_ip(ip)
        raise HTTPException(
            status_code=429, detail="Too many login attempts. Please try again later."
        )


async def block_ip(ip: str) -> None:
    """Block an IP address"""
    if not REDIS_CLIENT:
        return

    key = f"{SUSPICIOUS_IP_PREFIX}{ip}"
    REDIS_CLIENT.setex(key, BLOCK_DURATION, "1")


async def is_ip_blocked(ip: str) -> bool:
    """Check if an IP is blocked"""
    if not REDIS_CLIENT:
        return False

    return REDIS_CLIENT.exists(f"{SUSPICIOUS_IP_PREFIX}{ip}") == 1


def _get_client_ip(request: Request) -> str:
    """Get client IP from request, handling proxies"""
    forwarded = request.headers.get("X-Forwarded-For")
    return forwarded.split(",")[0].strip() if forwarded else request.client.host


# State management for OAuth
def generate_and_store_oauth_state() -> str:
    """Generate and store OAuth state parameter"""
    state = secrets.token_urlsafe(32)
    if REDIS_CLIENT:
        REDIS_CLIENT.setex(f"github_state:{state}", 300, "1")  # 5 minute TTL
    return state


def verify_oauth_state(state: str) -> bool:
    """Verify OAuth state parameter"""
    if not REDIS_CLIENT:
        logger.warning("Redis unavailable, OAuth state verification disabled")
        return True

    state_key = f"github_state:{state}"
    exists = REDIS_CLIENT.exists(state_key)
    if exists:
        REDIS_CLIENT.delete(state_key)
    return exists == 1
