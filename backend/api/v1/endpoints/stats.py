from api.v1.models.global_stats import GlobalStats
from api.v1.models.scan import Scan
from api.v1.services.auth_service import get_api_key
from fastapi import APIRouter, Depends

router = APIRouter()


@router.get("/global-stats", dependencies=[Depends(get_api_key)])
async def get_global_stats():
    stats = await GlobalStats.get_or_create()
    return {
        "total_scans": stats.total_scans,
        "total_paid_scans": stats.total_paid_scans,
        "total_unpaid_scans": stats.total_unpaid_scans,
        "total_findings": stats.total_findings,
        "total_lines_of_code": stats.total_lines_of_code,
        "scan_statuses": {
            "pending": await Scan.find(Scan.status == "pending").count(),
            "in_progress": await Scan.find(Scan.status == "in_progress").count(),
            "completed": await Scan.find(Scan.status == "completed").count(),
            "failed": await Scan.find(Scan.status == "failed").count(),
        },
    }
