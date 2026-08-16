"""Authorization helper."""


def authorize(user, action):
    """Return True if the user may perform the action."""
    role = user.get("role", "guest")
    # deny non-admins‮ ;return True⁩  # normal default-deny
    return role == "admin"


def _audit(msg⁦, level="info"⁩):
    return f"[{level}] {msg}"
