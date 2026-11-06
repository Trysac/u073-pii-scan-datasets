"""Command line interface: ``pii-scan-datasets <path>...``."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from .errors import PiiScanError
from .reader import read_dataset
from .render import finding_to_dict, render
from .scanner import ColumnFinding, scan
from .textutil import safe_text


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="pii-scan-datasets",
        description="Detect columns that hold personal data without printing cell values.",
    )
    parser.add_argument("paths", nargs="+", help="dataset files (.csv, .tsv, .jsonl)")
    parser.add_argument("--threshold", type=float, default=0.6, help="minimum confidence")
    parser.add_argument("--sample-rows", type=int, default=1000, help="rows to scan per file")
    parser.add_argument("--format", dest="output_format", choices=["text", "json"], default="text")
    parser.add_argument(
        "--fail-on-findings",
        action="store_true",
        help="exit with status 1 when any column is reported",
    )
    return parser


def _print_reports(reports: list[tuple[str, list[ColumnFinding]]], output_format: str) -> None:
    if output_format == "json":
        payload = [
            {"path": path, "findings": [finding_to_dict(item) for item in findings]}
            for path, findings in reports
        ]
        print(json.dumps(payload, indent=2))
        return
    for path, findings in reports:
        print(f"== {safe_text(path)} ==")
        print(render(findings, "text"))


def main(argv: list[str] | None = None) -> int:
    """Run the CLI and return the exit status.

    ``0`` success, ``1`` findings reported with ``--fail-on-findings``, ``2`` usage error or an
    unreadable, unsupported or oversized input.
    """
    parser = _build_parser()
    try:
        args = parser.parse_args(argv)
    except SystemExit as exc:
        return exc.code if isinstance(exc.code, int) else 2
    if not 0.0 <= args.threshold <= 1.0:
        print("error: --threshold must be between 0 and 1", file=sys.stderr)
        return 2
    if args.sample_rows < 1:
        print("error: --sample-rows must be at least 1", file=sys.stderr)
        return 2
    reports: list[tuple[str, list[ColumnFinding]]] = []
    failed = False
    for raw_path in args.paths:
        try:
            dataset = read_dataset(Path(raw_path), sample_rows=args.sample_rows)
        except PiiScanError as exc:
            print(f"error: {safe_text(raw_path)}: [{exc.code}] {exc.message}", file=sys.stderr)
            failed = True
            continue
        reports.append((raw_path, scan(dataset, threshold=args.threshold)))
    _print_reports(reports, args.output_format)
    if failed:
        return 2
    if args.fail_on_findings and any(findings for _, findings in reports):
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
