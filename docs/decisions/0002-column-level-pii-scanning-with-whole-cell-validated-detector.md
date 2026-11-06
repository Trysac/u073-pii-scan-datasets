# Column-level PII scanning with whole-cell validated detectors and header hints

Status: accepted (generated, pending human review)

## Context

Data shared with vendors often hides emails, phone numbers, cards and national ids in undeclared columns. Text-level NER engines are slow and need models, and any tool that prints samples becomes a disclosure channel itself.

## Decision

Scan column by column over a streamed sample (CSV, TSV, JSONL) with pure standard-library detectors that match the whole trimmed cell and use real checksums (Luhn, ISO 7064 mod 97, DNI/NIE letter). Combine the match ratio with header hints into a confidence, keep only counters in findings, errors and events, enforce size and depth limits before parsing, and expose a small API plus a CLI. Detectors take a context object so hint-dependent rules (phone, date of birth) and the IBAN table stay pure.

## Consequences

Fast, dependency-free and safe to run on large tables, and outputs cannot leak cell values by construction. The cost is that free text and rows beyond the sample are not covered, hint-only categories rely on header names, and SSN-shaped values may also be reported as phones because the spec's phone rule accepts separators.
