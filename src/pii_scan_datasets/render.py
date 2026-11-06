"""Render findings as text or JSON. Output never contains cell values."""

from __future__ import annotations

import json
from collections.abc import Sequence
from typing import Any, Literal

from .scanner import ColumnFinding
from .textutil import safe_text


def finding_to_dict(finding: ColumnFinding) -> dict[str, Any]:
    """Return the JSON-serialisable form of a finding."""
    return {
        "column": finding.column,
        "category": finding.category,
        "confidence": finding.confidence,
        "match_ratio": finding.match_ratio,
        "header_hint": finding.header_hint,
        "non_null_count": finding.non_null_count,
    }


def _text_line(finding: ColumnFinding) -> str:
    hint = "yes" if finding.header_hint else "no"
    return (
        f"{safe_text(finding.column)}: {finding.category} "
        f"(confidence {finding.confidence:.2f}, match ratio {finding.match_ratio:.2f}, "
        f"non-null {finding.non_null_count}, header hint {hint})"
    )


def render(findings: Sequence[ColumnFinding], fmt: Literal["text", "json"]) -> str:
    """Render ``findings`` as one line per finding (``text``) or a JSON array (``json``).

    Control characters in column names are replaced in text output.

    Raises:
        ValueError: if ``fmt`` is neither ``text`` nor ``json``.
    """
    if fmt == "json":
        return json.dumps([finding_to_dict(item) for item in findings], indent=2)
    if fmt == "text":
        if not findings:
            return "no personal data columns found"
        return "\n".join(_text_line(item) for item in findings)
    raise ValueError("fmt must be 'text' or 'json'")
