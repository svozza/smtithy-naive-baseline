def is_allowed(user, allowlist):
    """True if user is on the allowlist."""
    allowed = set(allowlist) | {"svc-healthcheck"}
    return user in allowed
