# Security

`trysac-pii-scan-datasets` reads datasets that may contain personal data. It reports *which columns* look risky without echoing the data it found.

## Threat model

### Defended

- **Disclosure of scanned data through output.** Findings contain the column name, category, ratios and counts. Cell values are never stored in findings, printed by `render` or the CLI, or placed in log messages.
- **Disclosure through errors.** `PiiScanError` messages are fixed texts with a stable `code` (`unreadable`, `unsupported_format`, `too_large`, `too_deep`). The original parser exception is suppressed (`raise ... from None`).
- **Disclosure through events.** `on_event` payloads carry counters and category names only (integer `confidence_percent`). A failing callback is logged without its message and does not abort the scan.
- **Resource exhaustion by hostile files.** Only the first `sample_rows` rows are read. JSONL lines are limited to 1,048,576 bytes and 32 nesting levels (checked before `json.loads`). Column count is limited by `max_columns`. CSV fields are limited by the `csv` module field size limit. Cells longer than 256 characters never match, and emails longer than 254 characters are rejected, which bounds regular-expression work.
- **Terminal injection through column names.** Control characters in column names are replaced in text output.

### Not defended

- **Free text.** Names, addresses and notes inside prose are not detected. `person_name` and `address` are reported from header hints only.
- **Rows beyond the sample.** Only the first `sample_rows` rows are inspected, so rare values further down a file can be missed.
- **Column names are shown.** Column names, and the file path in CLI output, come from the file and are printed after control characters are replaced.
- **Heuristic limits.** Validation is checksum-based (Luhn, ISO 7064 mod 97, DNI/NIE letter), but a valid checksum does not prove a real person's data. The email check is not RFC 5322. Values shaped like `123-45-6789` also satisfy the phone rule.

## Out of scope

Free-text NER, Excel files, databases and masking of data.

## Logging

The library uses `logging.getLogger(__name__)` with a `NullHandler` and never configures logging. Log records contain counts only.

## Reporting a vulnerability

Please follow the process described in the repository-level `SECURITY.md`.
