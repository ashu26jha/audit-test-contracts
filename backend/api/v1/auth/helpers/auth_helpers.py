import secrets
from datetime import datetime, timedelta, timezone

from fastapi import HTTPException, Request
from jose import jwt

from config import settings
from core.models.auth import BlacklistedToken, LoginAttempt, OAuthState
from core.utils.logger import logger

# Security related constants
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
            now = datetime.now(timezone.utc)
            expires_at = datetime.fromtimestamp(exp, timezone.utc)

            await BlacklistedToken(token=token, blacklisted_at=now, expires_at=expires_at).insert()
    except Exception as e:
        logger.error(f"Error blacklisting token: {str(e)}")
        raise HTTPException(status_code=500, detail="Error processing logout") from e


async def is_token_blacklisted(token: str) -> bool:
    """Check if a token is blacklisted"""
    try:
        blacklisted = await BlacklistedToken.find_one({"token": token})
        return blacklisted is not None
    except Exception as e:
        logger.error(f"Error checking blacklist: {str(e)}")
        return False


# Security functions
async def track_login_attempt(request: Request) -> None:
    """Track login attempts and block suspicious IPs"""
    ip = _get_client_ip(request)
    if await is_ip_blocked(ip):
        raise HTTPException(
            status_code=429, detail="Too many login attempts. Please try again later."
        )

    now = datetime.now(timezone.utc)
    attempt = await LoginAttempt.find_one({"ip_address": ip})

    if attempt:
        # Ensure last_attempt is UTC-aware when comparing
        last_attempt = attempt.last_attempt
        if not last_attempt.tzinfo:
            last_attempt = last_attempt.replace(tzinfo=timezone.utc)

        if (now - last_attempt).total_seconds() > 60:
            attempt.attempts = 1
        else:
            attempt.attempts += 1
        attempt.last_attempt = now
        await attempt.save()
    else:
        attempt = LoginAttempt(
            ip_address=ip,
            attempts=1,
            last_attempt=now,  # This is UTC-aware
        )
        await attempt.insert()

    if attempt.attempts > MAX_ATTEMPTS:
        await block_ip(ip)
        raise HTTPException(
            status_code=429, detail="Too many login attempts. Please try again later."
        )


async def block_ip(ip: str) -> None:
    """Block an IP address"""
    now = datetime.now(timezone.utc)
    blocked_until = now + timedelta(seconds=BLOCK_DURATION)

    attempt = await LoginAttempt.find_one({"ip_address": ip})
    if attempt:
        attempt.blocked_until = blocked_until
        await attempt.save()
    else:
        await LoginAttempt(
            ip_address=ip, attempts=MAX_ATTEMPTS + 1, last_attempt=now, blocked_until=blocked_until
        ).insert()


async def is_ip_blocked(ip: str) -> bool:
    """Check if an IP is blocked"""
    now = datetime.now(timezone.utc)
    attempt = await LoginAttempt.find_one({"ip_address": ip, "blocked_until": {"$gt": now}})
    return attempt is not None


def _get_client_ip(request: Request) -> str:
    """Get client IP from request, handling proxies"""
    forwarded = request.headers.get("X-Forwarded-For")
    return forwarded.split(",")[0].strip() if forwarded else request.client.host


# State management for OAuth
async def generate_and_store_oauth_state() -> str:
    """Generate and store OAuth state parameter"""
    state = secrets.token_urlsafe(32)
    now = datetime.now(timezone.utc)
    expires_at = now + timedelta(minutes=5)  # 5 minutes to match TTL

    try:
        logger.info(f"Generating new OAuth state. Raw state length: {len(state)}")
        logger.info(f"Generated state: {state}")  # This is safe to log as it's temporary

        oauth_state = OAuthState(state=state, created_at=now, expires_at=expires_at)
        await oauth_state.insert()

        # Verify it was stored correctly
        stored_state = await OAuthState.find_one({"state": state})
        if stored_state:
            logger.info(
                f"Successfully stored and verified OAuth state in database. Created at: {stored_state.created_at}, Expires at: {stored_state.expires_at}"
            )
        else:
            logger.error("Failed to verify stored OAuth state immediately after insertion")

        return state
    except Exception as e:
        logger.error(f"Error storing OAuth state: {str(e)}")
        raise HTTPException(status_code=500, detail="Error during authentication") from e


async def verify_oauth_state(state: str) -> bool:
    """Verify OAuth state parameter"""
    now = datetime.now(timezone.utc)
    logger.info(f"Verifying OAuth state. Received state length: {len(state)}")
    logger.info(f"Received state: {state}")

    oauth_state = await OAuthState.find_one({"state": state, "expires_at": {"$gt": now}})

    if oauth_state:
        logger.info(
            f"Found valid OAuth state, created at: {oauth_state.created_at}, expires at: {oauth_state.expires_at}"
        )
        await oauth_state.delete()
        return True

    # If not found, try to find any state to see if it expired
    expired_state = await OAuthState.find_one({"state": state})
    if expired_state:
        logger.error(
            f"Found expired OAuth state. Created at: {expired_state.created_at}, expired at: {expired_state.expires_at}, current time: {now}"
        )
    else:
        # Let's check for any recent states to see if there's a mismatch
        recent_states = await OAuthState.find(
            {"created_at": {"$gt": now - timedelta(minutes=10)}}
        ).to_list()
        if recent_states:
            logger.error(
                f"Recent states found but none match. Recent states: {[s.state for s in recent_states]}"
            )
        logger.error(f"OAuth state not found in database: {state}")

    return False
