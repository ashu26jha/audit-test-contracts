import os
from contextlib import asynccontextmanager

import certifi
import uvicorn
from apscheduler.schedulers.asyncio import AsyncIOScheduler
from beanie import init_beanie
from fastapi import FastAPI, HTTPException
from fastapi.exceptions import RequestValidationError
from fastapi.middleware.cors import CORSMiddleware
from fastapi.openapi.utils import get_openapi
from motor.motor_asyncio import AsyncIOMotorClient

from api.v1.router import router as api_v1_router
from config import settings
from core.models.credit_transaction import CreditTransaction
from core.models.docs import ReadmeDocs
from core.models.payment import Payment
from core.models.scan import Scan, ScanResult
from core.models.user import User
from core.utils.error_handling import (
    general_exception_handler,
    http_exception_handler,
    validation_exception_handler,
)
from core.utils.logger import logger
from core.utils.process_pool import ProcessPoolManager
from core.utils.slack import send_slack_message

# Create scheduler
scheduler = AsyncIOScheduler()


@asynccontextmanager
async def lifespan(app: FastAPI):
    # Initialize process pool
    process_pool = ProcessPoolManager.get_instance()

    if settings.SLACK_TOKEN:
        scheduler.add_job(
            send_slack_message,
            "cron",
            hour=15,
            minute=30,
            timezone="Asia/Kolkata",
        )
        scheduler.start()

    client = AsyncIOMotorClient(settings.MONGODB_URL, tlsCAFile=certifi.where())
    if settings.ENVIRONMENT == "development":
        db = client.audit_agent_dev
    elif settings.ENVIRONMENT == "staging":
        db = client.audit_agent_staging
    else:
        db = client.audit_agent
    logger.info("Connecting to MongoDB...")
    await init_beanie(
        database=db,
        document_models=[
            User,
            Scan,
            ScanResult,
            Payment,
            CreditTransaction,
            ReadmeDocs,
        ],
    )
    logger.info(f"Connected to MongoDB in {settings.ENVIRONMENT} environment.")
    yield
    logger.info("Closing MongoDB connection")
    client.close()
    logger.info("MongoDB connection closed")

    # Cleanup process pool
    process_pool.shutdown()
    logger.info("Process pool shutdown complete")


app = FastAPI(
    title=settings.TITLE,
    description=settings.DESCRIPTION,
    version=settings.VERSION,
    docs_url="/docs" if settings.ENVIRONMENT != "production" else None,
    redoc_url="/redoc" if settings.ENVIRONMENT != "production" else None,
    lifespan=lifespan,
)


app.add_middleware(
    CORSMiddleware,
    allow_origins=[settings.FRONTEND_URL],
    allow_credentials=True,
    allow_methods=["GET", "POST"],
    allow_headers=[
        "Content-Type",
        "Authorization",
        "X-API-Key",
        "Accept",
        "Origin",
    ],
    max_age=3600,  # Cache preflight requests for 1 hour
)


def custom_openapi():
    if app.openapi_schema:
        return app.openapi_schema
    openapi_schema = get_openapi(
        title=settings.TITLE,
        version=settings.VERSION,
        description=settings.DESCRIPTION,
        routes=app.routes,
    )
    app.openapi_schema = openapi_schema
    return app.openapi_schema


app.openapi = custom_openapi

app.include_router(api_v1_router)


app.add_exception_handler(HTTPException, http_exception_handler)
app.add_exception_handler(RequestValidationError, validation_exception_handler)
app.add_exception_handler(Exception, general_exception_handler)


if __name__ == "__main__":
    if settings.ENVIRONMENT == "development":
        # Use standard Uvicorn in development
        uvicorn.run(app, host="0.0.0.0", port=8000)
    else:
        # Use Gunicorn with config from gunicorn.conf.py
        os.environ["GUNICORN_WORKER"] = "1"
        os.system("gunicorn 'main:app' --config gunicorn.conf.py")
