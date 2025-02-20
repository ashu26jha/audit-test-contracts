from datetime import datetime, timezone

from core.utils.errors import ValidationError


def ensure_utc_datetime(v):
    """
    Convert a string or naive datetime into an aware datetime in UTC.

    Args:
        v: The value to convert. Can be None, a string in ISO format, or a datetime object.

    Returns:
        datetime: A timezone-aware datetime object in UTC.

    Raises:
        ValidationError: If the input value is not a valid datetime format or type.
    """
    if v is None:
        return v

    if isinstance(v, str):
        try:
            v = datetime.fromisoformat(v.replace("Z", "+00:00"))
        except ValueError:
            try:
                v = datetime.strptime(v, "%Y-%m-%dT%H:%M:%S.%f%z")
            except ValueError as e:
                raise ValidationError(
                    "Invalid datetime format",
                    details={
                        "value": v,
                        "expected_formats": [
                            "ISO format (e.g. 2024-01-11T12:00:00+00:00)",
                            "%Y-%m-%dT%H:%M:%S.%f%z",
                        ],
                    },
                ) from e

    if isinstance(v, datetime):
        if v.tzinfo is None:
            v = v.replace(tzinfo=timezone.utc)
        return v.astimezone(timezone.utc)

    raise ValidationError(
        "Invalid datetime value",
        details={
            "value": str(v),
            "type": type(v).__name__,
            "expected_types": ["str", "datetime", "None"],
        },
    )
