"""Helpers that keep untrusted text safe to print."""

from __future__ import annotations

MAX_TEXT_CHARS = 200


def safe_text(value: str, limit: int = MAX_TEXT_CHARS) -> str:
    """Return ``value`` with non-printable characters replaced and clipped to ``limit``."""
    cleaned = "".join(char if char.isprintable() else "?" for char in value)
    if len(cleaned) <= limit:
        return cleaned
    keep = limit - 3
    return cleaned[:keep] + "..."
