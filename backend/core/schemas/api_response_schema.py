from typing import Any, Generic, Optional, TypeVar

from pydantic import BaseModel

T = TypeVar("T")


class ErrorResponse(BaseModel):
    success: bool = False
    code: int
    message: str
    details: Optional[Any] = None


class SuccessResponse(BaseModel, Generic[T]):
    success: bool = True
    data: T
