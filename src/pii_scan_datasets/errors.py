"""Typed errors raised by the library."""

from __future__ import annotations

from typing import Literal

ErrorCode = Literal["unreadable", "unsupported_format", "too_large", "too_deep"]


class PiiScanError(Exception):
    """Base error of the library.

    ``code`` is a stable machine-readable identifier. Messages are fixed texts and never
    contain cell values.
    """

    def __init__(self, code: ErrorCode, message: str) -> None:
        super().__init__(message)
        self.code: ErrorCode = code
        self.message = message
