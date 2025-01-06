from typing import List, Optional

from pydantic import BaseModel


class SetupResult(BaseModel):
    project_dir: str
    project_type: str
    project_structure: str
    remappings: Optional[List[str]] = None
