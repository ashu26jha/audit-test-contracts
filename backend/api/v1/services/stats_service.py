from datetime import datetime, timedelta, timezone

from api.v1.models.scan import Scan
from api.v1.models.user import User
from common.logger import logger

TOTAL_FINDINGS = "$total_findings"
PAID_STATUS = "$paid_status"
DISCOUNT_APPLIED = "$discount_applied"


async def get_global_stats():
    """
    Retrieves global statistics about scans including totals for:
    - all scans
    - paid scans (broken down into regular paid, discounted, and free)
    - unpaid scans (only completed scans that require payment)
    - failed scans
    - findings
    - lines of code (only for completed scans)
    - status counts
    - total users
    - returning users (users with more than 1 scan)
    """
    try:
        pipeline = [
            {
                "$group": {
                    "_id": None,
                    "total_scans": {"$sum": 1},
                    "total_findings": {"$sum": {"$ifNull": [TOTAL_FINDINGS, 0]}},
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
                                        {"$eq": ["$status", "completed"]},
                                        {"$eq": [PAID_STATUS, True]},
                                        {"$eq": [{"$ifNull": [DISCOUNT_APPLIED, False]}, False]},
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
                                {
                                    "$and": [
                                        {"$eq": ["$status", "completed"]},
                                        {"$eq": [PAID_STATUS, True]},
                                        {"$eq": [{"$ifNull": [DISCOUNT_APPLIED, False]}, True]},
                                    ]
                                },
                                1,
                                0,
                            ]
                        }
                    },
                    "free_scans": {
                        "$sum": {
                            "$cond": [
                                {
                                    "$and": [
                                        {"$eq": ["$status", "completed"]},
                                        {"$lte": [{"$ifNull": [TOTAL_FINDINGS, 2]}, 1]},
                                    ]
                                },
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
                                        {"$eq": [PAID_STATUS, False]},
                                        {"$ne": ["$status", "failed"]},  # Exclude failed scans
                                        {
                                            "$gt": [{"$ifNull": [TOTAL_FINDINGS, 2]}, 1]
                                        },  # Exclude free scans
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

        # Pipeline to count returning users (users with more than 1 scan)
        returning_users_pipeline = [
            {"$group": {"_id": "$user_id", "scan_count": {"$sum": 1}}},
            {"$match": {"scan_count": {"$gt": 1}}},
            {"$count": "returning_users"},
        ]

        stats = await Scan.aggregate(pipeline).to_list(length=1)
        base_stats = stats[0] if stats else {}

        # Get returning users count
        returning_users_result = await Scan.aggregate(returning_users_pipeline).to_list(length=1)
        returning_users = (
            returning_users_result[0].get("returning_users", 0) if returning_users_result else 0
        )

        # Get scan statuses in a single query for efficiency
        status_counts = {
            status: await Scan.find({"status": status}).count()
            for status in ["pending", "in_progress", "completed", "failed"]
        }

        # Get total number of users
        total_users = await User.find().count()

        # Calculate total paid scans with breakdown
        regular_paid = base_stats.get("paid_scans", 0)
        discounted = base_stats.get("discounted_scans", 0)
        free = base_stats.get("free_scans", 0)

        return {
            "total_scans": base_stats.get("total_scans", 0),
            "total_users": total_users,
            "returning_users": returning_users,
            "total_paid_scans": {
                "total": regular_paid + discounted + free,
                "regular_paid": regular_paid,
                "discounted": discounted,
                "free": free,
            },
            "total_unpaid_scans": base_stats.get("unpaid_completed_scans", 0),
            "total_failed_scans": base_stats.get("failed_scans", 0),
            "total_findings": base_stats.get("total_findings", 0),
            "total_lines_of_code": base_stats.get("total_lines_of_code", 0),
            "scan_statuses": status_counts,
        }
    except Exception as e:
        logger.error(f"Error getting global stats: {str(e)}")
        raise


async def get_24h_stats():
    """
    Returns counts of scans, lines of code scanned,
    vulnerabilities found, regular paid scans, and
    new users within the last 24 hours.
    """
    now_utc = datetime.now(timezone.utc)
    twenty_four_hours_ago = now_utc - timedelta(hours=24)

    stats_24h_pipeline = [
        {"$match": {"createdAt": {"$gte": twenty_four_hours_ago}}},
        {
            "$group": {
                "_id": None,
                # Total lines of code from linesOfCode.total_lines
                "lines_of_code": {"$sum": {"$ifNull": ["$linesOfCode.total_lines", 0]}},
                # Count of all scans
                "total_scans_24h": {"$sum": 1},
                # Sum of total_findings for vulnerabilities
                "vulnerabilities_found": {"$sum": {"$ifNull": [TOTAL_FINDINGS, 0]}},
                # Count of paid scans (non-discounted, completed)
                "paid_scans_24h": {
                    "$sum": {
                        "$cond": [
                            {
                                "$and": [
                                    {"$eq": ["$status", "completed"]},
                                    {"$eq": [PAID_STATUS, True]},
                                    {"$eq": [{"$ifNull": [DISCOUNT_APPLIED, False]}, False]},
                                ]
                            },
                            1,
                            0,
                        ]
                    }
                },
            }
        },
    ]

    # Run aggregation
    scans_24h_results = await Scan.aggregate(stats_24h_pipeline).to_list(length=1)
    if scans_24h_results:
        lines_of_code = scans_24h_results[0].get("lines_of_code", 0)
        total_scans_24h = scans_24h_results[0].get("total_scans_24h", 0)
        vulnerabilities_found = scans_24h_results[0].get("vulnerabilities_found", 0)
        paid_scans_24h = scans_24h_results[0].get("paid_scans_24h", 0)
    else:
        lines_of_code = 0
        total_scans_24h = 0
        vulnerabilities_found = 0
        paid_scans_24h = 0

    # Number of users created in the last 24h
    new_users_in_24h = await User.find(User.createdAt >= twenty_four_hours_ago).count()

    return {
        "lines_of_code": lines_of_code,
        "total_scans_24h": total_scans_24h,
        "vulnerabilities_found": vulnerabilities_found,
        "paid_scans_24h": paid_scans_24h,
        "new_users": new_users_in_24h,
    }
