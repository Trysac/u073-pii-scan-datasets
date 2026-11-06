"""Streaming readers for CSV, TSV and JSONL datasets."""

from __future__ import annotations

import csv
import json
import logging
import re
from collections.abc import Iterator
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from .errors import PiiScanError

logger = logging.getLogger(__name__)

MAX_LINE_BYTES = 1_048_576
"""Maximum size in bytes of one JSONL line, excluding the line terminator."""

MAX_DEPTH = 32
"""Maximum nesting depth of objects and arrays in one JSONL line."""

_TOKEN = re.compile(rb'[\[\]{}"\\]')
_QUOTE = 34
_BACKSLASH = 92
_OPENERS = frozenset(b"{[")
_CLOSERS = frozenset(b"}]")


@dataclass(frozen=True)
class Dataset:
    """A sample of a tabular dataset.

    ``columns`` keeps the file order; every row maps each column to its text or ``None`` when
    the cell is missing or blank.
    """

    columns: list[str]
    rows: list[dict[str, str | None]]


def read_dataset(path: Path, *, sample_rows: int = 1000, max_columns: int = 1000) -> Dataset:
    """Read at most ``sample_rows`` rows of a ``.csv``, ``.tsv`` or ``.jsonl`` file.

    The file is streamed, never loaded whole. JSONL lines are limited to 1_048_576 bytes and
    32 nesting levels; objects are flattened with dot-joined keys and arrays become JSON
    strings.

    Raises:
        ValueError: if ``sample_rows`` or ``max_columns`` is below 1.
        PiiScanError: ``unsupported_format``, ``unreadable``, ``too_large`` or ``too_deep``.
    """
    if sample_rows < 1:
        raise ValueError("sample_rows must be at least 1")
    if max_columns < 1:
        raise ValueError("max_columns must be at least 1")
    path = Path(path)
    suffix = path.suffix.lower()
    if suffix in (".csv", ".tsv"):
        delimiter = "," if suffix == ".csv" else "\t"
        return _read_delimited(path, delimiter, sample_rows, max_columns)
    if suffix == ".jsonl":
        return _read_jsonl(path, sample_rows, max_columns)
    raise PiiScanError("unsupported_format", "only .csv, .tsv and .jsonl files are supported")


def _clean(value: str) -> str | None:
    return value if value.strip() else None


def _first_record(reader: Iterator[list[str]]) -> list[str] | None:
    for record in reader:
        if record:
            return record
    return None


def _unique_names(raw: list[str]) -> list[str]:
    seen: set[str] = set()
    names: list[str] = []
    for index, item in enumerate(raw, start=1):
        base = item.strip() or f"column_{index}"
        name = base
        counter = 2
        while name in seen:
            name = f"{base}_{counter}"
            counter += 1
        seen.add(name)
        names.append(name)
    return names


def _delimited_row(columns: list[str], record: list[str]) -> dict[str, str | None]:
    row: dict[str, str | None] = {}
    for index, name in enumerate(columns):
        row[name] = _clean(record[index]) if index < len(record) else None
    return row


def _csv_error(exc: csv.Error) -> PiiScanError:
    if "field larger than field limit" in str(exc):
        return PiiScanError("too_large", "a CSV field exceeds the field size limit")
    return PiiScanError("unreadable", "the file is not valid CSV")


def _read_delimited(path: Path, delimiter: str, sample_rows: int, max_columns: int) -> Dataset:
    try:
        with path.open(encoding="utf-8-sig", newline="") as handle:
            reader = csv.reader(handle, delimiter=delimiter)
            header = _first_record(reader)
            if header is None:
                return Dataset(columns=[], rows=[])
            columns = _unique_names(header)
            if len(columns) > max_columns:
                raise PiiScanError("too_large", "the dataset has more columns than allowed")
            rows: list[dict[str, str | None]] = []
            for record in reader:
                if not record:
                    continue
                rows.append(_delimited_row(columns, record))
                if len(rows) >= sample_rows:
                    break
    except csv.Error as exc:
        raise _csv_error(exc) from None
    except (OSError, UnicodeDecodeError):
        raise PiiScanError("unreadable", "the file cannot be read as UTF-8 text") from None
    logger.debug("read %d rows and %d columns", len(rows), len(columns))
    return Dataset(columns=columns, rows=rows)


def _check_depth(line: bytes) -> None:
    """Raise ``too_deep`` when brackets nest deeper than ``MAX_DEPTH`` (strings are skipped)."""
    depth = 0
    in_string = False
    escaped_at = -1
    for match in _TOKEN.finditer(line):
        index = match.start()
        if index == escaped_at:
            continue
        char = line[index]
        if in_string:
            if char == _BACKSLASH:
                escaped_at = index + 1
            elif char == _QUOTE:
                in_string = False
        elif char == _QUOTE:
            in_string = True
        elif char in _OPENERS:
            depth += 1
            if depth > MAX_DEPTH:
                raise PiiScanError("too_deep", "a JSONL line is nested deeper than 32 levels")
        elif char in _CLOSERS:
            depth = max(0, depth - 1)


def _scalar(value: Any) -> str | None:
    if value is None:
        return None
    if isinstance(value, str):
        return _clean(value)
    return json.dumps(value, separators=(",", ":"), ensure_ascii=False)


def _flatten(node: dict[str, Any], prefix: str, out: dict[str, str | None]) -> None:
    # Recursion is bounded: _check_depth already rejected lines nested deeper than MAX_DEPTH.
    for key, value in node.items():
        name = f"{prefix}.{key}" if prefix else key
        if isinstance(value, dict):
            if value:
                _flatten(value, name, out)
            else:
                out[name] = None
        else:
            out[name] = _scalar(value)


def _parse_line(line: bytes) -> dict[str, str | None]:
    _check_depth(line)
    try:
        value = json.loads(line.decode("utf-8-sig"))
    except ValueError:
        raise PiiScanError("unreadable", "a JSONL line is not valid JSON") from None
    if not isinstance(value, dict):
        raise PiiScanError("unreadable", "every JSONL line must be a JSON object")
    flat: dict[str, str | None] = {}
    _flatten(value, "", flat)
    return flat


def _read_jsonl(path: Path, sample_rows: int, max_columns: int) -> Dataset:
    columns: dict[str, None] = {}
    records: list[dict[str, str | None]] = []
    try:
        with path.open("rb") as handle:
            while len(records) < sample_rows:
                raw = handle.readline(MAX_LINE_BYTES + 2)
                if not raw:
                    break
                line = raw.rstrip(b"\r\n")
                if len(line) > MAX_LINE_BYTES:
                    raise PiiScanError("too_large", "a JSONL line exceeds 1048576 bytes")
                if not line.strip():
                    continue
                flat = _parse_line(line)
                for key in flat:
                    columns.setdefault(key, None)
                if len(columns) > max_columns:
                    raise PiiScanError("too_large", "the dataset has more columns than allowed")
                records.append(flat)
    except OSError:
        raise PiiScanError("unreadable", "the file cannot be read") from None
    names = list(columns)
    rows = [{name: record.get(name) for name in names} for record in records]
    logger.debug("read %d rows and %d columns", len(rows), len(names))
    return Dataset(columns=names, rows=rows)
