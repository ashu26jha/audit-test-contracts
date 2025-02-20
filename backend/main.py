import multiprocessing
from contextlib import asynccontextmanager

import uvicorn
from apscheduler.schedulers.asyncio import AsyncIOScheduler
from fastapi import FastAPI, HTTPException
from fastapi.exceptions import RequestValidationError
from fastapi.middleware.cors import CORSMiddleware
from fastapi.openapi.utils import get_openapi
from huey.consumer import Consumer

from api.v1.router import router as api_v1_router
from config import settings
from core.db.connection import (
    cleanup_huey_tasks,
    cleanup_login_attempts,
    close_database,
    huey,
    init_database,
)
from core.utils.error_handling import (
    audit_agent_exception_handler,
    general_exception_handler,
    http_exception_handler,
    validation_exception_handler,
)
from core.utils.errors import AuditAgentError
from core.utils.logger import logger
from core.utils.slack import send_slack_message

# Create scheduler
scheduler = AsyncIOScheduler()


@asynccontextmanager
async def lifespan(app: FastAPI):
    # Configure and start Huey consumer with multiple workers
    workers = max(2, multiprocessing.cpu_count() - 1)  # Use N-1 cores, minimum 2
    consumer = Consumer(
        huey,
        workers=workers,  # Multiple workers to leverage CPU cores
        worker_type="process",
        check_worker_health=True,
        health_check_interval=10,
    )
    consumer.start()
    logger.info(f"Huey consumer started with {workers} worker processes")

    if settings.SLACK_TOKEN:
        scheduler.add_job(
            send_slack_message,
            "cron",
            hour=15,
            minute=30,
            timezone="Asia/Kolkata",
        )

    # Login attempt cleanup job - run daily at 12:30 AM
    scheduler.add_job(
        cleanup_login_attempts,
        "interval",
        hours=24,
        name="cleanup_login_attempts",
        misfire_grace_time=3600,
    )

    # Huey tasks cleanup job - run daily at midnight
    scheduler.add_job(
        cleanup_huey_tasks,
        "cron",
        hour=0,
        minute=0,
        name="cleanup_huey_tasks",
        misfire_grace_time=3600,
    )

    scheduler.start()

    # Initialize database
    await init_database()

    yield

    # Cleanup
    await close_database()
    consumer.stop()
    logger.info("Huey consumer stopped")


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
app.add_exception_handler(AuditAgentError, audit_agent_exception_handler)
app.add_exception_handler(Exception, general_exception_handler)


if __name__ == "__main__":
    uvicorn.run(app, host="0.0.0.0", port=8000)
