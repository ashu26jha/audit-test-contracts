from datetime import datetime
from typing import List, Optional

from pydantic import BaseModel


class SetupResult(BaseModel):
    project_dir: str
    project_type: str
    project_structure: str
    remappings: Optional[List[str]] = None


class FreeScanStatus(BaseModel):
    """Status of free scan availability for a user."""

    is_allowed: bool
    next_available_at: datetime | None = None
