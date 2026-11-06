"""Detect columns holding personal data in CSV, TSV and JSONL datasets without printing values."""

from __future__ import annotations

import logging

from .detectors import (
    DEFAULT_DETECTORS,
    IBAN_LENGTHS,
    Detector,
    DetectorContext,
)
from .errors import PiiScanError
from .reader import Dataset, read_dataset
from .render import render
from .scanner import ColumnFinding, scan

__all__ = [
    "DEFAULT_DETECTORS",
    "IBAN_LENGTHS",
    "ColumnFinding",
    "Dataset",
    "Detector",
    "DetectorContext",
    "PiiScanError",
    "__version__",
    "read_dataset",
    "render",
    "scan",
]

__version__ = "0.1.0"

logging.getLogger(__name__).addHandler(logging.NullHandler())
