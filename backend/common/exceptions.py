from typing import Optional

from fastapi import HTTPException, status


class BaseAPIException(HTTPException):
    def __init__(self, status_code: int, detail: str):
        super().__init__(status_code=status_code, detail=detail)


class ResourceNotFoundError(BaseAPIException):
    def __init__(self, resource: str):
        super().__init__(status_code=status.HTTP_404_NOT_FOUND, detail=f"{resource} not found")


class UnauthorizedError(BaseAPIException):
    def __init__(self, detail: str = "Unauthorized access"):
        super().__init__(status_code=status.HTTP_401_UNAUTHORIZED, detail=detail)


class ValidationError(BaseAPIException):
    def __init__(self, detail: str):
        super().__init__(status_code=status.HTTP_400_BAD_REQUEST, detail=detail)


class InternalServerError(BaseAPIException):
    def __init__(self, details: Optional[str] = None):
        super().__init__(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Internal server error",
        )


class EmptyResponseError(BaseAPIException):
    def __init__(self):
        super().__init__(status_code=status.HTTP_204_NO_CONTENT, detail="Empty response from LLM")


class JSONParsingError(ValidationError):
    def __init__(self, detail: str = "Failed to parse LLM response as valid JSON"):
        super().__init__(detail=detail)


class NetworkError(InternalServerError):
    def __init__(self):
        super().__init__(details="A network error occurred while processing the response")


class InvalidFormatError(ValidationError):
    def __init__(self, detail: str):
        super().__init__(detail=detail)
