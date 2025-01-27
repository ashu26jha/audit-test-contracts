import os
from datetime import datetime, timedelta, timezone

import certifi
from beanie import init_beanie
from huey import SqliteHuey
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

# Create storage directory for SQLite databases if it doesn't exist
storage_dir = os.path.join(os.path.dirname(__file__), "storage")
os.makedirs(storage_dir, exist_ok=True)

# Initialize Huey with SQLite storage based on environment
if settings.ENVIRONMENT == "development":
    db_name = "audit_agent_dev_tasks.db"
elif settings.ENVIRONMENT == "staging":
    db_name = "audit_agent_staging_tasks.db"
else:  # production
    db_name = "audit_agent_tasks.db"

# Initialize Huey with environment-specific SQLite database in storage directory
huey = SqliteHuey(
    name="audit_agent",
    filename=os.path.join(storage_dir, db_name),
    immediate=False,  # Always run tasks in background workers
)

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


async def cleanup_huey_tasks():
    """Cleanup completed Huey tasks older than 7 days"""
    try:
        # Get the current database file based on environment
        if settings.ENVIRONMENT == "development":
            db_name = "audit_agent_dev_tasks.db"
        elif settings.ENVIRONMENT == "staging":
            db_name = "audit_agent_staging_tasks.db"
        else:  # production
            db_name = "audit_agent_tasks.db"

        db_path = os.path.join(storage_dir, db_name)
        if not os.path.exists(db_path):
            logger.info(f"No Huey database found at {db_path}")
            return

        # Calculate the cutoff timestamp (7 days ago)
        cutoff = datetime.now() - timedelta(days=7)
        cutoff_timestamp = int(cutoff.timestamp())

        # Clean up completed tasks older than the cutoff
        huey.storage.delete_older_than(cutoff_timestamp)
        logger.info(f"Cleaned up Huey tasks older than {cutoff.strftime('%Y-%m-%d %H:%M:%S')}")

    except Exception as e:
        logger.error(f"Error during Huey tasks cleanup: {str(e)}")
        # Don't raise the error to prevent scheduler from stopping
