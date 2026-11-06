# Project record

## Objective

Detect columns holding personal data in CSV, TSV and JSONL datasets with checksum-validated detectors and header hints, without printing cell values, so that risky columns can be flagged quickly.

## Scope

- In scope: `read_dataset`, `scan`, `render`, `PiiScanError`, the ten built-in detectors, and the `pii-scan-datasets` CLI, typed and tested.
- Out of scope: free-text NER, Excel files, databases, masking of data, and any runtime dependency.

## Timeline

| Date | Event |
|---|---|
| 2026 | Repository created from the factory utility template. |

## Effort metrics

Measured values only; a value that has not been measured stays "pending measurement".

| Metric | Value |
|---|---|
| Tokens (input / output) | 491804 / 102784 |
| Hours (human) | pending measurement |
| Cost (USD) | 0.8265 |

## Factory run u073 (measured from API usage)

| Phase | Model | Batch | Input | Output | Cache write | Cache read | Cost (USD) |
|---|---|---|---|---|---|---|---|
| generation | claude-sonnet-5-5 | yes | 2593 | 87115 | 0 | 4246 | 0.4386 |
| fix-1 | claude-sonnet-5-5 | no | 8 | 1144 | 7088 | 56255 | 0.0348 |
| audit | claude-sonnet-5-5 | no | 14 | 7131 | 46791 | 194870 | 0.2078 |
| fix-2 | claude-sonnet-5-5 | no | 14 | 2938 | 14241 | 119463 | 0.0770 |
| docs | claude-haiku-5-5 | no | 114341 | 4456 | 0 | 0 | 0.0683 |

Total: $0.8265. Prices: Anthropic list prices.
