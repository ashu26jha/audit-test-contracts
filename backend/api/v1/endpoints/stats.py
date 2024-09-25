from api.v1.models.global_stats import GlobalStats
from api.v1.models.scan import Scan
from fastapi import APIRouter

router = APIRouter()


@router.get("/global-stats")
async def get_global_stats():
    stats = await GlobalStats.get_or_create()
    return {
        "total_scans": stats.total_scans,
        "total_paid_scans": stats.total_paid_scans,
        "total_unpaid_scans": stats.total_unpaid_scans,
        "total_findings": stats.total_findings,
        "scan_statuses": {
            "pending": await Scan.find(Scan.status == "pending").count(),
            "in_progress": await Scan.find(Scan.status == "in_progress").count(),
            "completed": await Scan.find(Scan.status == "completed").count(),
            "failed": await Scan.find(Scan.status == "failed").count(),
        },
    }
