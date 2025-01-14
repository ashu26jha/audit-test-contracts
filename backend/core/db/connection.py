from datetime import datetime, timedelta, timezone

import certifi
from beanie import init_beanie
from motor.motor_asyncio import AsyncIOMotorClient

from config import settings
from core.models.auth import BlacklistedToken, LoginAttempt, OAuthState
from core.models.credit_transaction import CreditTransaction
from core.models.docs import ReadmeDocs
from core.models.payment import Payment
from core.models.scan import Scan, ScanResult
from core.models.throttling import ThrottleRecord
from core.models.user import User
from core.utils.logger import logger

# All document models that need to be initialized with Beanie
DOCUMENT_MODELS = [
    User,
    Scan,
    ScanResult,
    Payment,
    CreditTransaction,
    ReadmeDocs,
    BlacklistedToken,
    LoginAttempt,
    OAuthState,
    ThrottleRecord,
]

# Initialize MongoDB client
client = AsyncIOMotorClient(settings.MONGODB_URL, tlsCAFile=certifi.where())

# Select database based on environment
if settings.ENVIRONMENT == "development":
    db = client.audit_agent_dev
elif settings.ENVIRONMENT == "staging":
    db = client.audit_agent_staging
else:
    db = client.audit_agent


async def init_database():
    """Initialize database connection and Beanie models"""
    try:
        logger.info("Connecting to MongoDB...")
        await init_beanie(
            database=db,
            document_models=DOCUMENT_MODELS,
        )
        logger.info(f"Connected to MongoDB in {settings.ENVIRONMENT} environment.")
    except Exception as e:
        logger.error(f"Failed to initialize database: {str(e)}")
        raise


async def close_database():
    """Close database connection"""
    try:
        logger.info("Closing MongoDB connection")
        client.close()
        logger.info("MongoDB connection closed")
    except Exception as e:
        logger.error(f"Error closing database connection: {str(e)}")
        raise


async def cleanup_login_attempts():
    """Cleanup old login attempts (older than 24 hours)"""
    try:
        yesterday = datetime.now(timezone.utc) - timedelta(days=1)
        result = await LoginAttempt.find(
            {"last_attempt": {"$lt": yesterday}, "blocked_until": {"$lt": yesterday}}
        ).delete()

        if result and hasattr(result, "deleted_count"):
            logger.info(f"Cleaned up {result.deleted_count} old login attempts")
        else:
            logger.info("No old login attempts to clean up")

    except Exception as e:
        logger.error(f"Error during login attempts cleanup: {str(e)}")
        # Don't raise the error to prevent scheduler from stopping
