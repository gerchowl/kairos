"""HTML escaping helpers — use at EVERY interpolation of user-supplied data."""

from html import escape


def esc(value) -> str:
    """Escape for HTML text content and attribute values (quotes included)."""
    return escape(str(value if value is not None else ""), quote=True)
