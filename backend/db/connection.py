from __future__ import annotations

from config.settings import MONGODB_URL
from motor.motor_asyncio import AsyncIOMotorClient

client = AsyncIOMotorClient(MONGODB_URL)
database = client.DB_NAME
