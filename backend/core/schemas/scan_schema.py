from dataclasses import dataclass
from datetime import datetime
from enum import Enum
from typing import List, Optional
from uuid import UUID

from pydantic import BaseModel

from core.utils.profiles import Profiles


class SetupResult(BaseModel):
    project_dir: str
    project_type: str
    project_structure: str
    remappings: Optional[List[str]] = None


class FreeScanStatus(BaseModel):
    """Status of free scan availability for a user."""

    is_allowed: bool
    next_available_at: datetime | None = None


class ScanType(str, Enum):
    AUDIT_AGENT = "AUDIT_AGENT"
    AGENTIC = "AGENTIC"
    BENCHMARK = "BENCHMARK"


class ModeType(str, Enum):
    FEW_SHOTS = "FEW_SHOTS"
    VANILLA = "VANILLA"


class TypeOfScan(str, Enum):
    AUDIT_AGENT = "AUDIT_AGENT"
    MODEL = "MODEL"


@dataclass(kw_only=True)
class BaseScanContext:
    """Base context with common fields required by all scan types."""

    scan_id: UUID
    scan_number: int
    scan_type: ScanType
    user_id: str
    contract_files: List[str]
    is_subscription_scan: bool = False
    flattened_contracts: Optional[str] = None

    # Analysis related (common to all)
    detected_type: Optional[Profiles] = None
    summary_result: Optional[str] = None
