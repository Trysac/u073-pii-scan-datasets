"""Column scanning: apply detectors to a dataset and score every column."""

from __future__ import annotations

import logging
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass

from .detectors import (
    DEFAULT_DETECTORS,
    IBAN_LENGTHS,
    Detector,
    DetectorContext,
    header_matches,
)
from .reader import Dataset
from .textutil import safe_text

logger = logging.getLogger(__name__)

_MAX_MATCH_CHARS = 256
_HINT_FLOOR = 0.7
_HINT_BONUS = 0.2


@dataclass(frozen=True)
class ColumnFinding:
    """A column that probably holds personal data of one category.

    ``match_ratio`` is matches over non-null values; ``confidence`` adds the header-hint rule.
    No cell value is ever stored here.
    """

    column: str
    category: str
    confidence: float
    match_ratio: float
    header_hint: bool
    non_null_count: int


def _emit(
    on_event: Callable[[Mapping[str, str | int]], None] | None,
    payload: Mapping[str, str | int],
) -> None:
    if on_event is None:
        return
    try:
        on_event(payload)
    except Exception:
        logger.warning("on_event callback raised an exception; scanning continues")


def _non_null_values(dataset: Dataset, column: str) -> list[str]:
    values: list[str] = []
    for row in dataset.rows:
        cell = row.get(column)
        if cell is None:
            continue
        text = cell.strip()
        if text:
            values.append(text)
    return values


def _scan_column(
    column: str,
    values: list[str],
    detectors: Sequence[Detector],
    threshold: float,
    lengths: Mapping[str, int],
) -> list[ColumnFinding]:
    best: dict[str, ColumnFinding] = {}
    for detector in detectors:
        hint = header_matches(column, detector.header_hints)
        context = DetectorContext(header_hint=hint, iban_lengths=lengths)
        hits = sum(
            1
            for value in values
            if len(value) <= _MAX_MATCH_CHARS and detector.matches(value, context)
        )
        ratio = hits / len(values) if values else 0.0
        confidence = min(1.0, max(_HINT_FLOOR, ratio + _HINT_BONUS)) if hint else ratio
        if confidence <= 0.0 or confidence < threshold:
            continue
        candidate = ColumnFinding(
            column=column,
            category=detector.category,
            confidence=confidence,
            match_ratio=ratio,
            header_hint=hint,
            non_null_count=len(values),
        )
        current = best.get(detector.category)
        if current is None or candidate.confidence > current.confidence:
            best[detector.category] = candidate
    return sorted(best.values(), key=lambda finding: -finding.confidence)


def scan(
    dataset: Dataset,
    detectors: Sequence[Detector] = DEFAULT_DETECTORS,
    *,
    threshold: float = 0.6,
    iban_lengths: Mapping[str, int] | None = None,
    on_event: Callable[[Mapping[str, str | int]], None] | None = None,
) -> list[ColumnFinding]:
    """Scan every column of ``dataset`` and report the columns that look like personal data.

    ``match_ratio`` is matches over non-null values. ``confidence`` equals the ratio without a
    header hint and ``min(1.0, max(0.7, match_ratio + 0.2))`` with one. Per column, each
    category is reported once (best detector) when its confidence reaches ``threshold``;
    findings are ordered by dataset column order, then confidence descending.

    ``iban_lengths`` overrides the IBAN country length table. ``on_event`` receives counters
    only (never cell values); an exception raised by the callback is logged and ignored.

    Raises:
        ValueError: if ``threshold`` is outside ``[0, 1]``.
    """
    if not 0.0 <= threshold <= 1.0:
        raise ValueError("threshold must be between 0 and 1")
    lengths: Mapping[str, int] = IBAN_LENGTHS if iban_lengths is None else dict(iban_lengths)
    _emit(
        on_event,
        {
            "event": "scan_started",
            "columns": len(dataset.columns),
            "rows": len(dataset.rows),
        },
    )
    findings: list[ColumnFinding] = []
    for column in dataset.columns:
        values = _non_null_values(dataset, column)
        column_findings = _scan_column(column, values, detectors, threshold, lengths)
        for finding in column_findings:
            _emit(
                on_event,
                {
                    "event": "column_flagged",
                    "column": safe_text(finding.column),
                    "category": finding.category,
                    "confidence_percent": round(finding.confidence * 100),
                    "non_null_count": finding.non_null_count,
                },
            )
        findings.extend(column_findings)
    _emit(on_event, {"event": "scan_completed", "findings": len(findings)})
    logger.debug("scanned %d columns, %d findings", len(dataset.columns), len(findings))
    return findings
