from datetime import datetime, timezone


def ensure_utc_datetime(v):
    """Convert a string or naive datetime into an aware datetime in UTC."""
    if v is None:
        return v

    if isinstance(v, str):
        try:
            v = datetime.fromisoformat(v.replace("Z", "+00:00"))
        except ValueError:
            try:
                v = datetime.strptime(v, "%Y-%m-%dT%H:%M:%S.%f%z")
            except ValueError as e:
                raise ValueError("Invalid datetime format") from e

    if isinstance(v, datetime):
        if v.tzinfo is None:
            v = v.replace(tzinfo=timezone.utc)
        return v.astimezone(timezone.utc)

    raise ValueError("Invalid datetime value")
