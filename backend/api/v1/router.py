from fastapi import APIRouter

from config.settings import ENVIRONMENT

from .agentic import router as agentic_router
from .audit_agent import router as audit_agent_router
from .auth import router as auth_router
from .detectors import context_scan_router, fuzzer_router, static_analyzer_router
from .github import router as github_router
from .payments import router as payments_router
from .scans import router as scans_router
from .utilities.health_check import router as health_check_router
from .utilities.pdf import router as pdf_router
from .utilities.stats import router as stats_router

# Development-only imports
if ENVIRONMENT in ["development", "test"]:
    from .utilities.benchmark import router as benchmark_router
    from .utilities.critics import router as critics_router
    from .utilities.summary import router as summary_router

# Create the main v1 router
router = APIRouter(prefix="/api/v1", tags=["API v1"])

# Register all feature routers
router.include_router(health_check_router)
router.include_router(auth_router)
router.include_router(github_router)
router.include_router(audit_agent_router)
router.include_router(scans_router)
router.include_router(payments_router)
router.include_router(pdf_router)
router.include_router(stats_router)

# Register development-only routers
if ENVIRONMENT in ["development", "test"]:
    router.include_router(summary_router)
    router.include_router(context_scan_router)
    router.include_router(static_analyzer_router)
    router.include_router(fuzzer_router)
    router.include_router(critics_router)
    router.include_router(benchmark_router)
    router.include_router(agentic_router)
