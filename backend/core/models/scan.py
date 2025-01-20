# pylint: disable=too-many-ancestors,too-few-public-methods
from datetime import datetime, timezone
from typing import Dict, List, Optional
from uuid import UUID, uuid4

from beanie import Document, Indexed
from pydantic import BaseModel, ConfigDict, Field, field_validator

from core.utils.ensure_utc import ensure_utc_datetime
from core.utils.profiles import Profiles
from core.utils.severity import Severity


class Finding(BaseModel):
    """
    Represents a security finding in a codebase.
    Includes details about the issue, severity, affected contracts, and recommended fixes.
    """

    Issue: str = Field(..., description="A short description of the vulnerability or issue")
    Severity: str = Field(..., description="Severity level of the issue")
    Contracts: List[str] = Field(..., description="List of affected contract names")
    Description: str = Field(..., description="Detailed description of the issue")
    Recommendation: Optional[str] = Field(None, description="Suggested fix for the issue.")

    def __hash__(self):
        # Create a hash based on immutable fields that define a finding's identity
        return hash(
            (
                self.Issue,
                self.Severity,
                tuple(sorted(self.Contracts)),  # Convert list to tuple for hashing
                self.Description,
            )
        )

    def __eq__(self, other):
        if not isinstance(other, Finding):
            return False
        return (
            self.Issue == other.Issue
            and self.Severity == other.Severity
            and sorted(self.Contracts) == sorted(other.Contracts)
            and self.Description == other.Description
        )

    @field_validator("Severity", mode="before")
    @classmethod
    def validate_severity(cls, v: str) -> str:
        # Use the centralized Severity enum
        return Severity.from_str(v).value

    model_config = ConfigDict(from_attributes=True, populate_by_name=True)


class CodeAnalysisResult(BaseModel):
    """Tracks different types of lines in the codebase."""

    total_lines: int = Field(..., description="Total number of lines in the codebase")
    code_lines: int = Field(..., description="Number of lines containing code")
    comment_lines: int = Field(..., description="Number of comment lines")
    empty_lines: int = Field(..., description="Number of empty lines")
    string_lines: int = Field(default=0, description="Number of lines containing only strings")
    character_count: Optional[int] = Field(
        None, description="Total number of characters in the content"
    )
    non_whitespace_character_count: Optional[int] = Field(
        None, description="Number of non-whitespace characters in the content"
    )


class Scan(Document):
    """
    Main scan document model for database storage.
    Handles scan metadata, progress tracking, and results management.
    Can store both GitHub repository scans and contract address scans.
    """

    scan_id: UUID = Field(default_factory=uuid4, description="Unique identifier for the scan")
    scan_number: int = Field(default=0, description="Sequential number for user's scans")
    user_id: str = Indexed(description="GitHub ID or email of the user who initiated the scan")
    status: str = Field(..., description="Current status of the scan")
    startedAt: datetime = Field(
        default_factory=lambda: datetime.now(timezone.utc), description="When the scan was started"
    )
    completedAt: Optional[datetime] = Field(None, description="When the scan was completed")
    contractFiles: List[str] = Field(
        default_factory=list, description="List of contract files being scanned"
    )
    linesOfCode: Optional[CodeAnalysisResult] = Field(None, description="Code analysis metrics")
    repositoryURL: Optional[str] = Field(None, description="URL of the GitHub repository")
    repositoryName: Optional[str] = Field(None, description="Name of the repository")
    branchName: str = Field(default="main", description="Branch being scanned")
    contract_address: Optional[str] = Field(None, description="Contract address for agentic scans")
    chain_id: Optional[str] = Field(None, description="Chain ID for agentic scans")
    scan_type: Optional[str] = Field(None, description="Type of scan for agentic scans")
    commitHash: Optional[str] = Field(None, description="Commit hash being scanned")
    paid_status: bool = Field(default=False, description="Whether the scan has been paid for")
    discount_applied: bool = Field(default=False, description="Whether a discount was applied")
    total_findings: Optional[int] = Field(None, description="Total number of findings")
    createdAt: datetime = Field(
        default_factory=lambda: datetime.now(timezone.utc),
        description="When the scan record was created",
    )
    updatedAt: datetime = Field(
        default_factory=lambda: datetime.now(timezone.utc),
        description="When the scan record was last updated",
    )
    detectors: Dict[str, Optional[bool]] = Field(
        default_factory=dict, description="Status of each detector"
    )
    progress: float = Field(default=0.0, description="Scan progress percentage (0-100)")
    completed_detectors: int = Field(default=0, description="Number of completed detectors")
    total_detectors: int = Field(default=0, description="Total number of detectors to run")

    model_config = ConfigDict(
        from_attributes=True,
        json_schema_extra={
            "example": {
                "scan_id": "507f1f77bcf86cd799439012",
                "scan_number": 1,
                "user_id": "12345678",
                "status": "pending",
                "startedAt": "2023-10-01T11:00:00Z",
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
                "paid_status": False,
                "discount_applied": False,
                "createdAt": "2023-10-01T12:00:00Z",
                "updatedAt": "2023-10-01T12:52:12Z",
                "detectors": {
                    "context_scan_1": True,
                    "context_scan_2": True,
                    "context_scan_3": True,
                    "context_scan_4": True,
                    "static_analyzer": True,
                    "fuzzer": False,
                },
                "total_detectors": 5,
                "completed_detectors": 0,
                "progress": 0.0,
            }
        },
    )

    @field_validator("startedAt", "createdAt", "completedAt", "updatedAt", mode="before")
    @classmethod
    def ensure_utc(cls, v):
        return ensure_utc_datetime(v)

    @classmethod
    async def get_next_scan_number(cls, user_id: str) -> int:
        """Get the next sequential scan number for a user."""
        last_scan = await cls.find(cls.user_id == user_id).sort("-scan_number").limit(1).to_list()
        return (last_scan[0].scan_number + 1) if last_scan else 1

    @classmethod
    async def get_next_agentic_scan_number(cls, contract_address: str) -> int:
        """Get the next sequential scan number for a user."""
        last_scan = (
            await cls.find(cls.repositoryURL == contract_address)
            .sort("-scan_number")
            .limit(1)
            .to_list()
        )
        return (last_scan[0].scan_number + 1) if last_scan else 1

    class Settings:
        name = "scans"
        validate_on_save = True
        indexes = [
            [("scan_id", 1)],
            [("user_id", 1), ("createdAt", -1)],
            [("status", 1)],
            [("paid_status", 1)],
            [("repositoryURL", 1), ("branchName", 1)],
        ]


class ScanResult(Document):
    """
    Stores the detailed results of a scan.
    Includes findings, summary, and completion metadata.
    """

    scan_id: UUID = Indexed(unique=True, description="Reference to the parent scan")
    scan_number: int = Field(..., description="Sequential number matching parent scan")
    summary: Optional[str] = Field(None, description="Generated summary of findings")
    info_message: Optional[str] = Field(
        None, description="Additional information or status message"
    )
    type: Optional[Profiles] = Field(None, description="Type of scan profile used")
    total_findings: int = Field(default=0, description="Total number of findings")
    findings: List[Finding] = Field(default_factory=list, description="List of security findings")
    findings_before_removal: Optional[List[Finding]] = Field(
        None, description="Original findings before deduplication"
    )
    createdAt: datetime = Field(
        default_factory=lambda: datetime.now(timezone.utc),
        description="When the result was created",
    )
    completedAt: datetime = Field(
        default_factory=lambda: datetime.now(timezone.utc), description="When the scan completed"
    )

    model_config = ConfigDict(
        from_attributes=True,
        populate_by_name=True,
        json_schema_extra={
            "example": {
                "scan_id": "507f1f77bcf86cd799439012",
                "scan_number": 1,
                "summary": "Generated summary of the scan.",
                "info_message": "Optional info message",
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
                "createdAt": "2023-10-01T12:20:00Z",
                "completedAt": "2023-10-01T12:10:00Z",
            }
        },
    )

    @field_validator("createdAt", "completedAt", mode="before")
    @classmethod
    def ensure_utc(cls, v):
        return ensure_utc_datetime(v)

    class Settings:
        name = "scan_results"
        validate_on_save = True
        indexes = [[("scan_id", 1)], [("scan_number", 1)], [("type", 1)], [("total_findings", 1)]]
