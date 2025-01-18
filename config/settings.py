import os

MONGODB_URL = os.getenv("MONGODB_URL", "mongodb://localhost:27017")
TEST_MONGODB_URL = os.getenv("TEST_MONGODB_URL", "mongodb://localhost:27017/test_db")