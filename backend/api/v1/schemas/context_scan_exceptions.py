class ContextScanException(Exception):
    """Base exception class for context scan errors."""

    pass


class EmptyResponseError(ContextScanException):
    """Exception raised when the LLM response is empty."""

    pass


class InvalidJSONError(ContextScanException):
    """Exception raised when the LLM response does not contain valid JSON."""

    pass


class InvalidFormatError(ContextScanException):
    """Exception raised when the LLM response has an invalid format."""

    pass


class JSONParsingError(ContextScanException):
    """Exception raised when the JSON parsing fails."""

    pass


class NetworkError(ContextScanException):
    """Exception raised for network-related errors."""

    pass


class UnexpectedError(ContextScanException):
    """Exception raised for unexpected errors."""

    pass
