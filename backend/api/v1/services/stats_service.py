from api.v1.models.scan import Scan
from common.logger import logger


async def get_global_stats():
    """
    Retrieves global statistics about scans including totals for:
    - all scans
    - paid scans (broken down into regular paid and discounted)
    - unpaid scans (only completed scans that require payment)
    - failed scans
    - findings
    - lines of code (only for completed scans)
    - status counts
    """
    try:
        pipeline = [
            {
                "$group": {
                    "_id": None,
                    "total_scans": {"$sum": 1},
                    "total_findings": {"$sum": {"$ifNull": ["$total_findings", 0]}},
                    "total_lines_of_code": {
                        "$sum": {
                            "$cond": [
                                {"$eq": ["$status", "completed"]},
                                {"$ifNull": ["$linesOfCode.total_lines", 0]},
                                0,
                            ]
                        }
                    },
                    "paid_scans": {
                        "$sum": {
                            "$cond": [
                                {
                                    "$and": [
                                        {"$eq": ["$paid_status", True]},
                                        {"$eq": [{"$ifNull": ["$discount_applied", False]}, False]},
                                    ]
                                },
                                1,
                                0,
                            ]
                        }
                    },
                    "discounted_scans": {
                        "$sum": {
                            "$cond": [
                                {"$eq": [{"$ifNull": ["$discount_applied", False]}, True]},
                                1,
                                0,
                            ]
                        }
                    },
                    "failed_scans": {"$sum": {"$cond": [{"$eq": ["$status", "failed"]}, 1, 0]}},
                    "unpaid_completed_scans": {
                        "$sum": {
                            "$cond": [
                                {
                                    "$and": [
                                        {"$eq": ["$status", "completed"]},
                                        {"$eq": ["$paid_status", False]},
                                    ]
                                },
                                1,
                                0,
                            ]
                        }
                    },
                }
            }
        ]

        stats = await Scan.aggregate(pipeline).to_list(length=1)
        base_stats = stats[0] if stats else {}

        # Get scan statuses in a single query for efficiency
        status_counts = {
            status: await Scan.find({"status": status}).count()
            for status in ["pending", "in_progress", "completed", "failed"]
        }
        # Calculate total paid scans with breakdown
        regular_paid = base_stats.get("paid_scans", 0)
        discounted = base_stats.get("discounted_scans", 0)

        return {
            "total_scans": base_stats.get("total_scans", 0),
            "total_paid_scans": {
                "total": regular_paid + discounted,
                "regular_paid": regular_paid,
                "discounted": discounted,
            },
            "total_unpaid_scans": base_stats.get("unpaid_completed_scans", 0),
            "total_failed_scans": base_stats.get("failed_scans", 0),
            "total_findings": base_stats.get("total_findings", 0),
            "total_lines_of_code": base_stats.get("total_lines_of_code", 0),
            "scan_statuses": status_counts,
        }
    except Exception as e:
        logger.error(f"Error in stats aggregation: {str(e)}")
        raise
