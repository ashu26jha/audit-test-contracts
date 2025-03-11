from fastapi import APIRouter

from .autonomous_agent import router as autonomous_agent_base_router
from .context_scan import router as context_scan_base_router
from .fuzzer import router as fuzzer_base_router
from .multi_agents import router as multi_agent_base_router
from .static_analyzer import router as static_analyzer_base_router

# Create prefixed routers
detectors_prefix = "/detectors"

autonomous_agent_router = APIRouter(prefix=f"{detectors_prefix}", tags=["detectors"])
autonomous_agent_router.include_router(autonomous_agent_base_router)

context_scan_router = APIRouter(prefix=f"{detectors_prefix}", tags=["detectors"])
context_scan_router.include_router(context_scan_base_router)

fuzzer_router = APIRouter(prefix=f"{detectors_prefix}", tags=["detectors"])
fuzzer_router.include_router(fuzzer_base_router)

multi_agent_router = APIRouter(prefix=f"{detectors_prefix}", tags=["detectors"])
multi_agent_router.include_router(multi_agent_base_router)

static_analyzer_router = APIRouter(prefix=f"{detectors_prefix}", tags=["detectors"])
static_analyzer_router.include_router(static_analyzer_base_router)


__all__ = [
    "fuzzer_router",
    "context_scan_router",
    "static_analyzer_router",
    "autonomous_agent_router",
    "multi_agent_router",
]
