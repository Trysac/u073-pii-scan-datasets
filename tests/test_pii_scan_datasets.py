"""Behavior tests for the public API of pii_scan_datasets."""

from __future__ import annotations

import pytest

import pii_scan_datasets


def test_normalize_trims_and_lowercases() -> None:
    assert pii_scan_datasets.normalize("  Hello World ") == "hello world"


@pytest.mark.parametrize("value", ["", "   ", "\t\n"])
def test_normalize_rejects_blank_input(value: str) -> None:
    with pytest.raises(ValueError, match="must not be empty"):
        pii_scan_datasets.normalize(value)


def test_version_is_semver() -> None:
    parts = pii_scan_datasets.__version__.split(".")
    assert len(parts) == 3
    assert all(part.isdigit() for part in parts)
