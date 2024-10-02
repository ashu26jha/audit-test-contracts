from datetime import datetime, timezone

from beanie import Document
from pydantic import Field


class GlobalStats(Document):
    total_scans: int = Field(default=0)
    total_paid_scans: int = Field(default=0)
    total_unpaid_scans: int = Field(default=0)
    total_failed_scans: int = Field(default=0)
    total_findings: int = Field(default=0)
    last_updated: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))

    class Settings:
        name = "global_stats"

    @classmethod
    async def get_or_create(cls):
        stats = await cls.find_one()
        if not stats:
            stats = cls()
            await stats.create()
        return stats

    @classmethod
    async def increment_scan(cls, status: str, paid: bool, findings: int):
        stats = await cls.get_or_create()
        stats.total_scans += 1
        if status == "failed":
            stats.total_failed_scans += 1
        elif paid:
            stats.total_paid_scans += 1
        else:
            stats.total_unpaid_scans += 1
        stats.total_findings += findings
        stats.last_updated = datetime.now(timezone.utc)
        await stats.save()

    @classmethod
    async def update_paid_status(cls, old_status: str, new_status: str):
        stats = await cls.get_or_create()
        if old_status != new_status:
            if old_status == "failed":
                stats.total_failed_scans -= 1
            elif old_status == "paid":
                stats.total_paid_scans -= 1
            else:
                stats.total_unpaid_scans -= 1

            if new_status == "failed":
                stats.total_failed_scans += 1
            elif new_status == "paid":
                stats.total_paid_scans += 1
            else:
                stats.total_unpaid_scans += 1

            stats.last_updated = datetime.now(timezone.utc)
            await stats.save()

    @classmethod
    async def get_scans_by_status(cls, status: str) -> int:
        from api.v1.models.scan import Scan

        return await Scan.find(Scan.status == status).count()

    @classmethod
    async def get_findings_by_user(cls, user_id: str) -> int:
        from api.v1.models.scan import Scan

        pipeline = [
            {"$match": {"user_id": user_id}},
            {"$group": {"_id": None, "total_findings": {"$sum": "$total_findings"}}},
        ]
        result = await Scan.aggregate(pipeline).to_list(length=1)
        return result[0]["total_findings"] if result else 0
