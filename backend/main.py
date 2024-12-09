import os
from contextlib import asynccontextmanager

import certifi
import uvicorn
from beanie import init_beanie
from fastapi import Depends, FastAPI, HTTPException
from fastapi.exceptions import RequestValidationError
from fastapi.middleware.cors import CORSMiddleware
from fastapi.openapi.utils import get_openapi
from fastapi.security import HTTPBasic, HTTPBasicCredentials
from motor.motor_asyncio import AsyncIOMotorClient

from api.v1.auth import github_auth
from api.v1.endpoints import (
    audit_agent,
    context_scan,
    fuzzer,
    generate_pdf,
    generate_summary,
    github,
    health_check,
    scan_history,
    scan_results,
    static_analyzer,
    stats,
    test_auth,
)
from api.v1.endpoints.payments import create_stripe_session, stripe_webhook
from api.v1.models.payment import Payment
from api.v1.models.scan import Scan, ScanResult
from api.v1.models.user import User
from common import logger
from common.error_handling import (
    general_exception_handler,
    http_exception_handler,
    validation_exception_handler,
)
from config import settings


@asynccontextmanager
async def lifespan(app: FastAPI):
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
        ],
    )
    logger.info(f"Connected to MongoDB in {settings.ENVIRONMENT} environment.")
    yield
    logger.info("Closing MongoDB connection")
    client.close()
    logger.info("MongoDB connection closed")


app = FastAPI(
    title="Smart Contract Audit API",
    description="API for auditing smart contracts and detecting vulnerabilities",
    version="0.2.0",
    docs_url="/docs",
    redoc_url="/redoc",
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

security = HTTPBasic()


def authenticate(credentials: HTTPBasicCredentials = Depends(security)):
    correct_username = os.getenv("API_USERNAME", "")
    correct_password = os.getenv("API_PASSWORD", "")
    if credentials.username != correct_username or credentials.password != correct_password:
        raise HTTPException(status_code=401, detail="Invalid credentials")
    return credentials.username


def custom_openapi():
    if app.openapi_schema:
        return app.openapi_schema
    openapi_schema = get_openapi(
        title="Smart Contract Audit API",
        version="1.0.0",
        description="This API provides endpoints for auditing smart contracts, detecting vulnerabilities, and evaluating results.",
        routes=app.routes,
    )
    app.openapi_schema = openapi_schema
    return app.openapi_schema


app.openapi = custom_openapi

# Include routers
app.include_router(health_check.router, prefix="/api/v1")
app.include_router(github_auth.router, prefix="/api/v1/auth")
app.include_router(github.router, prefix="/api/v1/github")
app.include_router(audit_agent.router, prefix="/api/v1")  # Admin protected
app.include_router(scan_results.router, prefix="/api/v1/scans")  # Full results Admin protected
app.include_router(scan_history.router, prefix="/api/v1")
app.include_router(create_stripe_session.router, prefix="/api/v1/payments")
app.include_router(stripe_webhook.router, prefix="/api/v1/payments")
app.include_router(generate_pdf.router, prefix="/api/v1")  # Admin protected + Throttled (1mn)
app.include_router(stats.router, prefix="/api/v1")  # Admin protected

if settings.ENVIRONMENT in ["development", "test"]:
    app.include_router(generate_summary.router, prefix="/api/v1")
    app.include_router(context_scan.router, prefix="/api/v1")
    app.include_router(test_auth.router, prefix="/api/v1")
    app.include_router(fuzzer.router, prefix="/api/v1")
    app.include_router(static_analyzer.router, prefix="/api/v1")


app.add_exception_handler(HTTPException, http_exception_handler)
app.add_exception_handler(RequestValidationError, validation_exception_handler)
app.add_exception_handler(Exception, general_exception_handler)


if __name__ == "__main__":
    uvicorn.run(app, host="0.0.0.0", port=8000)
