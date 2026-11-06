# Architecture

## Purpose

`trysac-pii-scan-datasets` is a small, dependency-free Python library (module `pii_scan_datasets`) that detects columns holding personal data in CSV, TSV and JSONL datasets using checksum-validated detectors and header hints, without printing cell values.

## Shape

```text
caller code --> pii_scan_datasets (public API in __init__.py)
                    |
                    +-- reader.py    streaming CSV/TSV/JSONL sampling
                    +-- detectors.py whole-cell validators and header hints
                    +-- scanner.py   per-column scoring and thresholding
                    +-- render.py    text and JSON output without values
                    +-- errors.py    PiiScanError with stable codes
                    +-- __main__.py  CLI: pii-scan-datasets <path>...
```

- **Public API**: the names listed in `__all__` of `src/pii_scan_datasets/__init__.py`. Anything else is internal.
- **Errors**: invalid arguments raise `ValueError`; file problems raise `PiiScanError` with a fixed message.
- **Side effects**: file reads only, in `reader.py` and the CLI. Logging goes through `logging.getLogger(__name__)` with a `NullHandler`.

## Quality contract

The gates are defined in `scripts/check.py`; see [TESTING.md](TESTING.md).

## Decisions

Architecture decisions are recorded in [decisions/](decisions/) as numbered ADRs.
