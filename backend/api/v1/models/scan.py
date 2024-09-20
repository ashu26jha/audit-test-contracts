from datetime import datetime, timezone
from typing import List, Optional
from uuid import UUID, uuid4

from api.v1.schemas.context_scan_schema import Finding
from beanie import Document, Indexed
from common.profiles import Profiles
from pydantic import Field


class Scan(Document):
    scan_id: UUID = Field(default_factory=uuid4)
    user_id: str = Indexed()
    status: str
    startedAt: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    completedAt: Optional[datetime] = None
    contractFiles: List[str] = Field(default_factory=list)
    paid_status: bool = False
    createdAt: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    updatedAt: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))

    class Settings:
        name = "scans"

    class Config:
        from_attributes = True
        json_schema_extra = {
            "example": {
                "scan_id": "0e4e9e7c-d3a6-4f7a-9b6e-8d57b9f87e26",
                "user_id": "612e3a5e630d2b1a6f20fb4b",
                "status": "pending",
                "startedAt": "2023-10-01T12:00:00Z",
                "completedAt": None,
                "contractFiles": ["contracts/MyContract.sol"],
                "paidStatus": False,
                "createdAt": "2023-10-01T12:00:00Z",
                "updatedAt": "2023-10-01T12:00:00Z",
            }
        }


class ScanResult(Document):
    scan_id: UUID = Indexed(unique=True)
    summary: Optional[str]
    type: Optional[Profiles]
    findings: List[Finding] = Field(default_factory=list)
    createdAt: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    updatedAt: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))

    class Settings:
        name = "scan_results"

    class Config:
        from_attributes = True
        populate_by_name = True
        json_schema_extra = {
            "example": {
                "scan_id": "0e4e9e7c-d3a6-4f7a-9b6e-8d57b9f87e26",
                "summary": "Generated summary of the scan.",
                "type": "DEFAULT",
                "findings": [
                    {
                        "Issue": "Reentrancy Vulnerability",
                        "Severity": "High",
                        "Contracts": ["MyContract.sol"],
                        "Description": "Potential reentrancy in function withdraw().",
                        "Recommendation": "Use mutex or check-effects-interactions pattern.",
                    }
                ],
                "createdAt": "2023-10-01T12:00:00Z",
                "updatedAt": "2023-10-01T12:00:00Z",
            }
        }
