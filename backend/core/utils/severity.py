from enum import Enum

from core.utils.logger import logger


class Severity(Enum):
    HIGH = "High"
    MEDIUM = "Medium"
    LOW = "Low"
    INFO = "Info"
    BEST_PRACTICES = "Best Practices"

    @classmethod
    def from_str(cls, value: str) -> "Severity":
        """
        Convert string to Severity enum, with fallback handling.

        Args:
            value: The string value to convert. Can be None.

        Returns:
            Severity: The corresponding severity level, defaults to INFO for unknown values.
        """
        if not value:
            return cls.INFO

        # Normalize the input
        value_upper = value.upper()

        # Direct mapping from various severity formats to our enum
        mapping = {
            # Standard values
            "HIGH": cls.HIGH,
            "MEDIUM": cls.MEDIUM,
            "LOW": cls.LOW,
            "INFO": cls.INFO,
            "BEST PRACTICES": cls.BEST_PRACTICES,
            # Common variations
            "INFORMATIONAL": cls.INFO,
            "INFORMATION": cls.INFO,
            "CRITICAL": cls.HIGH,
            "WARNING": cls.MEDIUM,
            "OPTIMIZATION": cls.BEST_PRACTICES,
            "GAS": cls.BEST_PRACTICES,
            "NC": cls.BEST_PRACTICES,  # Non-Critical
            "QA": cls.BEST_PRACTICES,  # Quality Assurance
        }

        if value_upper in mapping:
            return mapping[value_upper]

        # Unknown severity fallback
        logger.warning(f"Unknown severity '{value}', defaulting to 'Info'")
        return cls.INFO

    @classmethod
    def validate(cls, value) -> "Severity":
        """
        Validate and convert a value to a Severity enum.

        This method centralizes the validation logic for Severity values,
        handling both enum instances and string values.

        Args:
            value: The value to validate. Can be a Severity enum or a string.

        Returns:
            Severity: A valid Severity enum instance.
        """
        # If already a Severity enum, return it directly
        if isinstance(value, cls):
            return value

        # Otherwise, convert string to Severity enum
        return cls.from_str(value)

    def __str__(self):
        """String representation of the enum value."""
        return self.value

    def __repr__(self):
        """Representation of the enum value."""
        return f"{self.__class__.__name__}.{self.name}"

    def to_json(self):
        """Convert the enum to a JSON serializable format."""
        return self.value
