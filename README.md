# pii-scan-datasets

[![PyPI version](https://img.shields.io/pypi/v/trysac-pii-scan-datasets)](https://pypi.org/project/trysac-pii-scan-datasets/)
[![License: MIT](https://img.shields.io/pypi/l/trysac-pii-scan-datasets)](LICENSE)
[![CI](https://github.com/Trysac/u073-pii-scan-datasets/actions/workflows/ci.yml/badge.svg)](https://github.com/Trysac/u073-pii-scan-datasets/actions/workflows/ci.yml)

Detect columns holding personal data in CSV, TSV and JSONL datasets with checksum-validated detectors and header hints, never printing cell values

## Problem

Describe in two or three sentences the concrete problem this utility solves, who hits it, and what
they do today without it. Replace this paragraph when the first real feature lands.

## Install

```sh
pip install trysac-pii-scan-datasets
# or
uv add trysac-pii-scan-datasets
```

Requires Python 3.10 or newer. No runtime dependencies.

## Usage

```python
import pii_scan_datasets

# normalize() trims surrounding whitespace and lower-cases the text.
print(pii_scan_datasets.normalize("  Hello World "))  # -> "hello world"

# Blank input is rejected explicitly instead of returning an empty string.
try:
    pii_scan_datasets.normalize("   ")
except ValueError as exc:
    print(f"rejected: {exc}")
```

## Documentation

- [Architecture](docs/ARCHITECTURE.md) and [decisions](docs/decisions/)
- [Testing](docs/TESTING.md) and [security](docs/SECURITY.md)
- [Project record](docs/PROJECT.md) and [stack](docs/STACK.md)
- [Changelog](CHANGELOG.md) and [contributing guide](CONTRIBUTING.md)

## License

[MIT](LICENSE) (c) 2026 Miguel Gomez
