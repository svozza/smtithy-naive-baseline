import os

from app.parse import build_url


def loader_url():
    """Build the service URL from environment configuration."""
    return build_url(os.environ["HOST"], os.environ.get("PORT", ""))
