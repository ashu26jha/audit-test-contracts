from __future__ import annotations

import os

import uvicorn
from api.v1.endpoints import (
    audit_agent,
    context_scan,
    critics,
    generate_summary,
    health_check,
    github,
)
from fastapi import Depends, FastAPI, HTTPException, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.openapi.utils import get_openapi
from fastapi.security import HTTPBasic, HTTPBasicCredentials
from motor.motor_asyncio import AsyncIOMotorClient
import config.settings as settings
from beanie import init_beanie
from contextlib import asynccontextmanager
from api.v1.models.user import User
from api.v1.auth import github_auth


@asynccontextmanager
async def lifespan(app: FastAPI):
    client = AsyncIOMotorClient(settings.MONGODB_URL)
    print("Connecting to MongoDB...")
    await init_beanie(database=client.myapp, document_models=[User])
    print("Connected to MongoDB")
    yield
    print("Closing MongoDB connection")
    client.close()
    print("MongoDB connection closed")


app = FastAPI(
    title="Smart Contract Audit API",
    description="API for auditing smart contracts and detecting vulnerabilities",
    version="1.0.0",
    docs_url="/docs",
    redoc_url="/redoc",
    lifespan=lifespan,
)
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

security = HTTPBasic()


# @app.on_event("startup")
# async def startup_event():
#     client = AsyncIOMotorClient(settings.MONGODB_URL)
#     await init_beanie(database=client.myapp, document_models=[User])


def authenticate(credentials: HTTPBasicCredentials = Depends(security)):
    correct_username = os.getenv("API_USERNAME", "")
    correct_password = os.getenv("API_PASSWORD", "")
    if credentials.username != correct_username or credentials.password != correct_password:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid credentials",
            headers={"WWW-Authenticate": "Basic"},
        )
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

app.include_router(health_check.router, prefix="/api/v1")
app.include_router(audit_agent.router, prefix="/api/v1")
app.include_router(generate_summary.router, prefix="/api/v1")
app.include_router(context_scan.router, prefix="/api/v1")
app.include_router(critics.router, prefix="/api/v1")
app.include_router(github.router, prefix="/api/v1/github")
app.include_router(github_auth.router, prefix="/api/v1/auth")

if __name__ == "__main__":
    uvicorn.run(app, host="0.0.0.0", port=8000)
