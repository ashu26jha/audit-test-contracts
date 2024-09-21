from typing import Any, Optional

from pydantic import BaseModel


class ErrorResponse(BaseModel):
    success: bool = False
    code: int
    message: str
    details: Optional[Any] = None


class SuccessResponse(BaseModel):
    success: bool = True
    data: Any


class APIResponse(BaseModel):
    success: bool
    data: Any = None
    error: ErrorResponse | None = None
