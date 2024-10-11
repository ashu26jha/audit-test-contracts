# pylint: disable=too-many-ancestors,too-few-public-methods
from datetime import datetime, timezone
from typing import Dict, List, Optional
from uuid import UUID, uuid4

from beanie import Document, Indexed
from pydantic import ConfigDict, Field

from api.v1.schemas.context_scan_schema import Finding
from common.profiles import Profiles


class Scan(Document):
    scan_id: UUID = Field(default_factory=uuid4)
    scan_number: int = Field(default=0)
    user_id: str = Indexed()
    status: str
    startedAt: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    completedAt: Optional[datetime] = None
    contractFiles: List[str] = Field(default_factory=list)
    linesOfCode: Optional[Dict[str, int]] = None
    repositoryURL: Optional[str] = None
    repositoryName: Optional[str] = None
    branchName: str = Field(default="main")
    commitHash: Optional[str] = None
    paid_status: bool = False
    total_findings: Optional[int] = None
    createdAt: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    updatedAt: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))

    model_config = ConfigDict(
        from_attributes=True,
        json_schema_extra={
            "example": {
                "_id": "507f1f77bcf86cd799439011",
                "scan_id": "507f1f77bcf86cd799439012",
                "scan_number": 1,
                "user_id": "612e3a5e630d2b1a6f20fb4b",
                "status": "pending",
                "startedAt": "2023-10-01T12:00:00Z",
                "completedAt": None,
                "contractFiles": ["contracts/MyContract.sol"],
                "linesOfCode": {
                    "total_lines": 100,
                    "code_lines": 80,
                    "comment_lines": 15,
                    "empty_lines": 5,
                },
                "repositoryURL": "https://github.com/user/repo",
                "repositoryName": "repo",
                "branchName": "main",
                "commitHash": "1234567890",
                "total_findings": 1,
                "paidStatus": False,
                "createdAt": "2023-10-01T12:00:00Z",
                "updatedAt": "2023-10-01T12:00:00Z",
            }
        },
    )

    class Settings:
        name = "scans"

    @classmethod
    async def get_next_scan_number(cls, user_id: str) -> int:
        last_scan = await cls.find(cls.user_id == user_id).sort("-scan_number").limit(1).to_list()
        return (last_scan[0].scan_number + 1) if last_scan else 1


class ScanResult(Document):
    scan_id: UUID = Indexed(unique=True)
    scan_number: int
    summary: Optional[str]
    type: Optional[Profiles]
    total_findings: int = Field(default=0)
    findings: List[Finding] = Field(default_factory=list)
    createdAt: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    completedAt: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))

    model_config = ConfigDict(
        from_attributes=True,
        populate_by_name=True,
        json_schema_extra={
            "example": {
                "_id": "507f1f77bcf86cd799439012",
                "scan_id": "507f1f77bcf86cd799439012",
                "scan_number": 1,
                "summary": "Generated summary of the scan.",
                "type": "DEFAULT",
                "total_findings": 1,
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
                "completedAt": "2023-10-01T12:00:00Z",
            }
        },
    )

    class Settings:
        name = "scan_results"
