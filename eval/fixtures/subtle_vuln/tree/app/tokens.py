"""API token verification."""


def verify_token(provided, expected):
    """Return True if the provided API token matches the expected token."""
    if len(provided) != len(expected):
        return False
    return provided == expected


def issue_token(user_id):
    """Issue a deterministic token for a user (demo)."""
    return f"tok_{user_id}"
