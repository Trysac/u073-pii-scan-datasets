# pii-scan-datasets

[![PyPI version](https://img.shields.io/pypi/v/trysac-pii-scan-datasets)](https://pypi.org/project/trysac-pii-scan-datasets/)
[![License: MIT](https://img.shields.io/pypi/l/trysac-pii-scan-datasets)](LICENSE)
[![CI](https://github.com/Trysac/u073-pii-scan-datasets/actions/workflows/ci.yml/badge.svg)](https://github.com/Trysac/u073-pii-scan-datasets/actions/workflows/ci.yml)

Detect columns holding personal data in CSV, TSV and JSONL datasets with checksum-validated detectors and header hints, never printing cell values

## Problem

Data shared with vendors or loaded into analytics tools often carries emails, phone numbers, card numbers or national ids in columns nobody declared. Text-level PII engines need language models and are slow on large tables. This column-level scanner uses validated detectors to flag risky columns quickly, without printing the data it found.

## Install

```sh
pip install trysac-pii-scan-datasets
# or
uv add trysac-pii-scan-datasets
```

Requires Python 3.10 or newer. No runtime dependencies.

## Usage

```python
from pathlib import Path

from pii_scan_datasets import read_dataset, render, scan

dataset = read_dataset(Path("data.csv"))
findings = scan(dataset)
print(render(findings, "text"))
```

### CLI

```sh
pii-scan-datasets data.csv --fail-on-findings
```

Options: `--threshold` (default 0.6), `--sample-rows` (default 1000), `--format text|json` (default text) and `--fail-on-findings`.

Exit codes: `0` nothing reported (or findings without `--fail-on-findings`), `1` findings reported with `--fail-on-findings`, `2` usage error or an unreadable, unsupported or oversized input.

### Public API

- `read_dataset(path, *, sample_rows=1000, max_columns=1000) -> Dataset`: reads at most `sample_rows` rows of `.csv`, `.tsv` or `.jsonl`. JSONL lines are limited to 1,048,576 bytes and 32 nesting levels; objects are flattened with dot-joined keys and arrays become JSON strings.
- `scan(dataset, detectors=DEFAULT_DETECTORS, *, threshold=0.6, iban_lengths=None, on_event=None) -> list[ColumnFinding]`: `threshold` must lie in [0, 1]; `on_event` receives counters only.
- `render(findings, fmt) -> str`: `fmt` is `"text"` or `"json"`.
- `PiiScanError` with `code` in `unreadable`, `unsupported_format`, `too_large`, `too_deep`. Messages are fixed texts.
- Errors: `ValueError` for invalid `sample_rows`, `max_columns`, `threshold` or `fmt`.

### Detectors

email, phone, payment_card (Luhn), iban (mod-97), ip_address, us_ssn, es_dni_nie, date_of_birth (header hint plus ISO date), person_name and address (header hints only).

### Limits

Only the first `sample_rows` rows are inspected. Cells longer than 256 characters never match. Emails longer than 254 characters are rejected.

## Why not Presidio?

Presidio is the best-known alternative for PII detection in text. This library does not use NLP models; it validates whole cells with checksums and header hints at column level.

## Security

See [security](docs/SECURITY.md) for the threat model.

## Documentation

- [Architecture](docs/ARCHITECTURE.md) and [decisions](docs/decisions/)
- [Testing](docs/TESTING.md) and [security](docs/SECURITY.md)
- [Project record](docs/PROJECT.md) and [stack](docs/STACK.md)
- [Changelog](CHANGELOG.md) and [contributing guide](CONTRIBUTING.md)

## License

[MIT](LICENSE) (c) 2026 Miguel Gomez
