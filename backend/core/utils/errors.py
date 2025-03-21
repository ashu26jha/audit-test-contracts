# pylint: disable=unnecessary-pass
"""
Custom exceptions for the Audit Agent application.
These exceptions represent different types of errors that can occur during the audit process.
"""


class AuditAgentError(Exception):
    """Base exception class for all Audit Agent errors."""

    def __init__(self, message: str, details: dict = None):
        self.message = message
        self.details = details
        super().__init__(self.message)


# Repository-related errors
class RepositoryError(AuditAgentError):
    """Base class for repository-related errors."""

    pass


class CloneError(RepositoryError):
    """Raised when repository cloning fails."""

    pass


class BranchError(RepositoryError):
    """Raised when branch operations fail."""

    pass


class ContractError(RepositoryError):
    """Raised when contract file operations fail."""

    pass


# Scan-related errors
class ScanError(AuditAgentError):
    """Base class for scan-related errors."""

    pass


class InitializationError(ScanError):
    """Raised when scan initialization fails."""

    pass


class ValidationError(ScanError):
    """Raised when scan validation fails."""

    pass


class DetectorError(ScanError):
    """Raised when a detector fails."""

    pass


class CriticError(ScanError):
    """Raised when a critic fails."""

    pass


# Payment and credit-related errors
class PaymentError(AuditAgentError):
    """Base class for payment-related errors."""

    pass


class PaymentConfigError(PaymentError):
    """Raised when payment configuration fails."""

    pass


class CreditError(PaymentError):
    """Raised when credit operations fail."""

    pass


class SubscriptionError(PaymentError):
    """Raised when subscription-related operations fail."""

    pass


# Authentication and authorization errors
class AuthError(AuditAgentError):
    """Base class for authentication-related errors."""

    pass


class TokenError(AuthError):
    """Raised when token operations fail."""

    pass


class AuthorizationError(AuthError):
    """Raised when permission checks fail."""

    pass


# Environment and configuration errors
class EnvironmentError(AuditAgentError):
    """Base class for environment-related errors."""

    pass


class ConfigurationError(EnvironmentError):
    """Raised when configuration is invalid or missing."""

    pass


class UnsupportedOperationError(EnvironmentError):
    """Raised when a context doesn't support required operations."""

    pass


class DependencyError(EnvironmentError):
    """Raised when required dependencies are missing or incompatible."""

    pass


# LLM-related errors
class LLMError(AuditAgentError):
    """Base class for LLM-related errors."""

    pass


class ModelError(LLMError):
    """Raised when LLM model operations fail."""

    pass


class PromptError(LLMError):
    """Raised when prompt generation or processing fails."""

    pass


# Database errors
class DatabaseError(AuditAgentError):
    """Base class for database-related errors."""

    pass


class ConnectionError(DatabaseError):
    """Raised when database connection fails."""

    pass


class QueryError(DatabaseError):
    """Raised when database query fails."""

    pass


# Rate limiting errors
class RateLimitError(AuditAgentError):
    """Raised when rate limits are exceeded."""

    pass


# HTTP errors
class HTTPClientError(AuditAgentError):
    """Raised when HTTP client operations fail."""

    pass


# Tools-related errors
class ToolError(AuditAgentError):
    """Base class for tool-related errors."""

    pass


class SearchError(ToolError):
    """Raised when search operations fail."""

    pass


class ParsingError(ToolError):
    """Raised when content parsing fails."""

    pass


class QueryGenerationError(ToolError):
    """Raised when query generation fails."""

    pass


class EtherscanError(ToolError):
    """Raised when Etherscan operations fail."""

    pass


class PDFGenerationError(ToolError):
    """Raised when PDF generation fails."""

    pass


class ReportError(ToolError):
    """Raised when report generation or delivery fails."""

    pass
