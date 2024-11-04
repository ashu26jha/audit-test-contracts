from enum import Enum


class Severity(Enum):
    HIGH = "High"
    MEDIUM = "Medium"
    LOW = "Low"
    INFO = "Info"
    BEST_PRACTICES = "Best Practices"

    @classmethod
    def from_str(cls, value: str) -> "Severity":
        """Convert string to Severity enum, with fallback handling."""
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

        return mapping.get(value_upper, cls.INFO)
