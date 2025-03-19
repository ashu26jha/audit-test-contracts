from fastapi import APIRouter

from .agentic import router as agentic_base_router
from .audit_agent import router as audit_agent_base_router
from .benchmark import router as benchmark_base_router
from .cairo import router as cairo_base_router

# Create prefixed routers
scanner_prefix = "/scanner"

audit_agent_router = APIRouter(prefix=f"{scanner_prefix}")
audit_agent_router.include_router(audit_agent_base_router)

agentic_router = APIRouter(prefix=f"{scanner_prefix}")
agentic_router.include_router(agentic_base_router)

benchmark_router = APIRouter(prefix=f"{scanner_prefix}")
benchmark_router.include_router(benchmark_base_router)

cairo_router = APIRouter(prefix=f"{scanner_prefix}")
cairo_router.include_router(cairo_base_router)

__all__ = [
    "agentic_router",
    "audit_agent_router",
    "benchmark_router",
    "cairo_router",
]
