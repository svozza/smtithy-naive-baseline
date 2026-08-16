"""String coercion helpers."""


def to_int(value, default=0):
    """Return value as an int, or default when it cannot be coerced."""
    try:
        return int(value)
    except (TypeError, ValueError):
        return default
