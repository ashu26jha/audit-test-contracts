from redis import Redis
from redis.exceptions import RedisError

from config import settings
from core.utils.logger import logger

# Initialize Redis client
REDIS_CLIENT = None

try:
    REDIS_CLIENT = Redis.from_url(settings.REDIS_URL, decode_responses=True)
    REDIS_CLIENT.ping()
    logger.info("Successfully connected to Redis")
except RedisError as e:
    logger.warning(f"Redis unavailable, some features will be limited: {str(e)}")
    REDIS_CLIENT = None
