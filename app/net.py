"""Small HTTP helpers."""


def get_json(session, url):
    """Return the JSON body of a GET, or None on a non-200."""
    resp = session.get(url, timeout=10)
    if resp.status_code != 200:
        return None
    return resp.json()
