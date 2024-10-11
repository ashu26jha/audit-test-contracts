from __future__ import annotations

from motor.motor_asyncio import AsyncIOMotorClient

from config.settings import MONGODB_URL

client = AsyncIOMotorClient(MONGODB_URL)
database = client.DB_NAME
