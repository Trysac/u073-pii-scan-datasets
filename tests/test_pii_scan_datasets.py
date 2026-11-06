"""Tests for the pii_scan_datasets public API."""

from __future__ import annotations

import csv
import json
import logging
import runpy
import warnings
from collections.abc import Mapping
from dataclasses import FrozenInstanceError
from pathlib import Path

import pytest

import pii_scan_datasets
from pii_scan_datasets import (
    DEFAULT_DETECTORS,
    IBAN_LENGTHS,
    ColumnFinding,
    Dataset,
    Detector,
    DetectorContext,
    PiiScanError,
    read_dataset,
    render,
    scan,
)
from pii_scan_datasets.__main__ import main
from pii_scan_datasets.detectors import header_matches
from pii_scan_datasets.textutil import safe_text

MAX_LINE = 1_048_576
SENTINEL = "SENTINEL-CELL-7Q2Z"

CARD_OK = ["4111111111111111", "4111 1111 1111 1111", "4111-1111-1111-1111"]
CARD_BAD = [
    "4111111111111112",
    "4111 1111 1111 1111 12/27",
    "4111111111111111 123",
    "4111111111111111x",
    "x4111111111111111",
    "4111111111111111.",
    "411111111111",
    "41111111111111111111",
    "",
]
IBAN_OK = [
    "DE89370400440532013000",
    "BE68 5390 0754 7034",
    "GB82 WEST 1234 5698 7654 32",
    "FR1420041010050500013M02606",
    "de89370400440532013000",
]
IBAN_BAD = [
    "DE89370400440532013001",
    "XX89370400440532013000",
    "BE68 5390 0754 7034 EUR",
    "DE89370400440532013000,",
    "DE89-3704-0044-0532-0130-00",
    "DE",
    "",
]
PHONE_OK = ["+34 612 345 678", "(555) 123-4567", "+14155552671", "555.123.4567", "612-345-678"]
PHONE_BAD = [
    "2024-01-15",
    "1.234.567",
    "12.345.678",
    "123456",
    "+1234567890123456",
    "4111 1111 1111 1111",
    "555-1234 ext 5",
    "+34 612 345 678 x",
    "++34612345678",
    "12+3456789",
    "+",
    "",
]
IP_OK = ["192.168.1.1", "::1", "2001:db8::1"]
IP_BAD = ["1.2.3.4.5", "256.1.1.1", "192.168.1.1/24", "192.168.1.1 ", "1.2.3", "1", ""]
SSN_OK = ["123-45-6789", "899-45-6789", "001-01-0001"]
SSN_BAD = [
    "000-45-6789",
    "666-45-6789",
    "900-45-6789",
    "999-45-6789",
    "123-00-6789",
    "123-45-0000",
    "123456789",
    "123-45-678",
    "123-45-6789x",
    "x123-45-6789",
]
DNI_OK = ["12345678Z", "X1234567L", "x1234567l", "Y1234567X", "Z1234567R"]
DNI_BAD = ["12345678A", "12345678", "X123456L", "12345678Z1", "W1234567L", "1234567Z", ""]

HOSTILE = {
    "too_deep": f'{{"s": "{SENTINEL}", "d": ' + "[" * 40 + "]" * 40 + "}",
    "too_large": f'{{"s": "{SENTINEL}", "pad": "' + "x" * (MAX_LINE + 1) + '"}',
    "unreadable": f'{{"s": "{SENTINEL}" oops}}',
}


def detector(name: str) -> Detector:
    return next(item for item in DEFAULT_DETECTORS if item.name == name)


def matches(name: str, value: str, *, hint: bool = False) -> bool:
    context = DetectorContext(header_hint=hint, iban_lengths=IBAN_LENGTHS)
    return detector(name).matches(value, context)


def column_dataset(column: str, values: list[str | None]) -> Dataset:
    return Dataset(columns=[column], rows=[{column: value} for value in values])


def write_text(tmp_path: Path, name: str, text: str) -> Path:
    path = tmp_path / name
    path.write_text(text, encoding="utf-8", newline="")
    return path


def starts_with(prefix: str):  # type: ignore[no-untyped-def]
    def check(value: str, context: DetectorContext) -> bool:
        return value.startswith(prefix)

    return check


# ----------------------------------------------------------------------------- detectors


def test_default_detectors_are_the_ten_specified() -> None:
    names = [item.name for item in DEFAULT_DETECTORS]
    assert names == [
        "email",
        "phone",
        "payment_card",
        "iban",
        "ip_address",
        "us_ssn",
        "es_dni_nie",
        "date_of_birth",
        "person_name",
        "address",
    ]


def test_header_hints_are_exactly_the_specified_set() -> None:
    spec = (
        "email correo phone telefono movil card tarjeta iban ip ssn dni nie nif cedula name "
        "first_name last_name nombre apellido address direccion birth dob fecha_nacimiento"
    )
    found = {hint for item in DEFAULT_DETECTORS for hint in item.header_hints}
    assert found == set(spec.split())


def test_iban_table_is_exactly_the_registry_extract() -> None:
    spec = (
        "AD=24 AT=20 BE=16 BG=22 CH=21 CY=28 CZ=24 DE=22 DK=18 EE=20 ES=24 FI=18 FR=27 GB=22 "
        "GI=23 GR=27 HR=21 HU=28 IE=22 IS=26 IT=27 LI=21 LT=20 LU=20 LV=21 MC=27 MT=31 NL=18 "
        "NO=15 PL=28 PT=25 RO=24 SE=24 SI=19 SK=24 SM=27 VA=22"
    )
    expected = {item.split("=")[0]: int(item.split("=")[1]) for item in spec.split()}
    assert dict(IBAN_LENGTHS) == expected
    assert len(IBAN_LENGTHS) == 37
    with pytest.raises(TypeError):
        IBAN_LENGTHS["XX"] = 1  # type: ignore[index]


@pytest.mark.parametrize("value", CARD_OK)
def test_card_accepts_luhn_valid(value: str) -> None:
    assert matches("payment_card", value)


@pytest.mark.parametrize("value", CARD_BAD)
def test_card_rejects_invalid_and_neighbours(value: str) -> None:
    assert not matches("payment_card", value)


@pytest.mark.parametrize("value", IBAN_OK)
def test_iban_accepts_valid(value: str) -> None:
    assert matches("iban", value)


@pytest.mark.parametrize("value", IBAN_BAD)
def test_iban_rejects_invalid_and_neighbours(value: str) -> None:
    assert not matches("iban", value)


def test_iban_rejects_non_ascii_letters() -> None:
    assert not matches("iban", "\u00dfE89370400440532013000")


@pytest.mark.parametrize("value", PHONE_OK)
def test_phone_accepts_explicit_formats(value: str) -> None:
    assert matches("phone", value)


@pytest.mark.parametrize("value", PHONE_BAD)
def test_phone_rejects_even_under_header_hint(value: str) -> None:
    assert not matches("phone", value)
    assert not matches("phone", value, hint=True)


def test_plain_digits_are_phones_only_with_header_hint() -> None:
    assert not matches("phone", "5551234567")
    assert matches("phone", "5551234567", hint=True)
    assert matches("phone", "1234567", hint=True)


@pytest.mark.parametrize("value", IP_OK)
def test_ip_accepts(value: str) -> None:
    assert matches("ip_address", value)


@pytest.mark.parametrize("value", IP_BAD)
def test_ip_rejects(value: str) -> None:
    assert not matches("ip_address", value)


@pytest.mark.parametrize("value", SSN_OK)
def test_ssn_accepts(value: str) -> None:
    assert matches("us_ssn", value)


@pytest.mark.parametrize("value", SSN_BAD)
def test_ssn_rejects(value: str) -> None:
    assert not matches("us_ssn", value)


@pytest.mark.parametrize("value", DNI_OK)
def test_dni_nie_accepts(value: str) -> None:
    assert matches("es_dni_nie", value)


@pytest.mark.parametrize("value", DNI_BAD)
def test_dni_nie_rejects(value: str) -> None:
    assert not matches("es_dni_nie", value)


def test_acceptance_literals_documented() -> None:
    """A column named 'c1' with 8 valid emails out of 10 non-null values is reported as 'email'.

    Rejects group '00' and serial '0000'; both report category 'national_id'.
    """
    assert detector("us_ssn").category == "national_id"
    assert not matches("us_ssn", "123-00-6789")
    assert not matches("us_ssn", "123-45-0000")


def test_both_national_id_detectors_share_the_category() -> None:
    assert detector("es_dni_nie").category == "national_id"
    assert detector("us_ssn").category == "national_id"


@pytest.mark.parametrize(
    "value",
    ["a@example.com", "first.last+tag@sub.example.org"],
)
def test_email_accepts(value: str) -> None:
    assert matches("email", value)


@pytest.mark.parametrize(
    "value",
    [
        "a@b.c",
        "a@@example.com",
        "@example.com",
        "a b@example.com",
        "a@example.com b@example.com",
        "plain",
        "a@example",
        "x" * 65 + "@example.com",
        "a@" + "b" * 300 + ".com",
    ],
)
def test_email_rejects(value: str) -> None:
    assert not matches("email", value)


def test_birth_date_needs_hint_and_valid_iso_date() -> None:
    assert matches("date_of_birth", "1990-05-17", hint=True)
    assert not matches("date_of_birth", "1990-05-17")
    for bad in ("1990-13-45", "1990-02-30", "17/05/1990", "1990-05-17T00:00"):
        assert not matches("date_of_birth", bad, hint=True)


def test_name_and_address_never_match_values() -> None:
    for name in ("person_name", "address"):
        assert not matches(name, "Ana Garcia", hint=True)


@pytest.mark.parametrize(
    ("header", "hints", "expected"),
    [
        ("Email", ("email",), True),
        ("user.email", ("email",), True),
        ("E-Mail", ("email",), False),
        ("First Name", ("first_name",), True),
        ("first-name", ("first_name",), True),
        ("first.name", ("first_name",), True),
        ("name_first", ("first_name",), False),
        ("zip", ("ip",), False),
        ("ip_address", ("ip",), True),
        ("DNI", ("dni",), True),
        ("Correo Electronico", ("correo",), True),
        ("c1", ("email", "correo"), False),
        ("", ("dni",), False),
    ],
)
def test_header_matches(header: str, hints: tuple[str, ...], expected: bool) -> None:
    assert header_matches(header, hints) is expected


def test_detector_and_finding_are_immutable() -> None:
    with pytest.raises(FrozenInstanceError):
        detector("email").name = "other"  # type: ignore[misc]
    finding = ColumnFinding("c", "email", 1.0, 1.0, False, 1)
    with pytest.raises(FrozenInstanceError):
        finding.column = "d"  # type: ignore[misc]


# ----------------------------------------------------------------------------- scan


def test_email_column_acceptance() -> None:
    valid = [f"user{index}@example.com" for index in range(8)]
    values: list[str | None] = [*valid, "not-an-email", "user@host", None, None]
    findings = scan(column_dataset("c1", values))
    assert len(findings) == 1
    finding = findings[0]
    assert finding.column == "c1"
    assert finding.category == "email"
    assert finding.match_ratio == 0.8
    assert finding.confidence == 0.8
    assert finding.non_null_count == 10
    assert finding.header_hint is False


def test_header_only_columns_get_confidence_point_seven() -> None:
    dataset = Dataset(
        columns=["DNI", "First Name", "fecha_nacimiento"],
        rows=[{"DNI": "zzz", "First Name": "Ana", "fecha_nacimiento": "unknown"}],
    )
    findings = scan(dataset)
    by_column = {item.column: item for item in findings}
    assert len(findings) == 3
    assert by_column["DNI"].category == "national_id"
    assert by_column["First Name"].category == "person_name"
    assert by_column["fecha_nacimiento"].category == "date_of_birth"
    for item in findings:
        assert item.confidence == 0.7
        assert item.header_hint is True
        assert item.match_ratio == 0.0


def test_threshold_controls_reporting() -> None:
    values: list[str | None] = [f"u{index}@example.com" for index in range(11)]
    values.extend(["plain text"] * 9)
    dataset = column_dataset("c1", values)
    low = scan(dataset, threshold=0.5)
    assert len(low) == 1
    assert low[0].confidence == 0.55
    assert scan(dataset) == []


def test_threshold_must_be_a_probability() -> None:
    with pytest.raises(ValueError, match="threshold"):
        scan(column_dataset("c1", ["x"]), threshold=1.5)
    with pytest.raises(ValueError, match="threshold"):
        scan(column_dataset("c1", ["x"]), threshold=-0.1)


def test_hint_boosts_confidence_and_caps_at_one() -> None:
    half: list[str | None] = ["a@example.com", "nope"] * 5
    boosted = scan(column_dataset("email", half))
    assert boosted[0].confidence == pytest.approx(0.7)
    assert boosted[0].match_ratio == 0.5
    full = scan(column_dataset("user_email", ["a@example.com", "b@example.com"]))
    assert full[0].confidence == 1.0
    assert full[0].header_hint is True


def test_dates_and_thousands_are_not_phones_even_under_phone_header() -> None:
    findings = scan(column_dataset("phone", ["2024-01-15", "1.234.567"]))
    assert len(findings) == 1
    assert findings[0].category == "phone"
    assert findings[0].match_ratio == 0.0
    assert findings[0].header_hint is True


def test_card_and_iban_columns_by_value() -> None:
    cards = scan(column_dataset("c1", ["4111111111111111", "4111 1111 1111 1111"]))
    assert [item.category for item in cards] == ["payment_card"]
    ibans = scan(column_dataset("c1", ["DE89370400440532013000", "  BE68 5390 0754 7034  "]))
    assert [item.category for item in ibans] == ["iban"]
    assert ibans[0].match_ratio == 1.0


def test_iban_lengths_override() -> None:
    dataset = column_dataset("c1", ["DE89370400440532013000"] * 3)
    assert [item.category for item in scan(dataset)] == ["iban"]
    assert scan(dataset, iban_lengths={"DE": 21}) == []


def test_dni_and_ssn_columns_report_national_id() -> None:
    dni = scan(column_dataset("c2", ["12345678Z", "X1234567L"]))
    assert {item.category for item in dni} == {"national_id"}
    ssn = scan(column_dataset("ssn", ["123-45-6789", "899-45-6789"]))
    national = [item for item in ssn if item.category == "national_id"]
    assert len(national) == 1
    assert national[0].header_hint is True
    assert national[0].confidence == 1.0


def test_birth_date_column_needs_header() -> None:
    values: list[str | None] = ["1990-05-17", "1985-12-01"]
    assert scan(column_dataset("c1", values)) == []
    findings = scan(column_dataset("dob", values))
    assert findings[0].category == "date_of_birth"
    assert findings[0].match_ratio == 1.0


def test_ip_column() -> None:
    findings = scan(column_dataset("ip", ["10.0.0.1", "::1"]))
    assert [item.category for item in findings] == ["ip_address"]
    assert findings[0].confidence == 1.0


def test_blank_cells_are_null_and_long_cells_never_match() -> None:
    values: list[str | None] = ["a@example.com", "   ", "", None, "y" * 300 + "@example.com"]
    findings = scan(column_dataset("c1", values), threshold=0.4)
    assert findings[0].non_null_count == 2
    assert findings[0].match_ratio == 0.5


def test_findings_are_ordered_and_merged_by_category() -> None:
    detectors = (
        Detector("b-det", "cat_b", starts_with("b")),
        Detector("a-det", "cat_a", starts_with("a")),
        Detector("a2-det", "cat_a", starts_with("b")),
    )
    findings = scan(column_dataset("c1", ["a", "a", "a", "b", "b"]), detectors, threshold=0.3)
    assert [(item.category, item.confidence) for item in findings] == [
        ("cat_a", 0.6),
        ("cat_b", 0.4),
    ]


def test_findings_follow_dataset_column_order() -> None:
    row = {"z": "a@example.com", "a": "b@example.com"}
    findings = scan(Dataset(columns=["z", "a"], rows=[row]))
    assert [item.column for item in findings] == ["z", "a"]


def test_empty_detector_list_and_empty_dataset() -> None:
    assert scan(column_dataset("c1", ["a@example.com"]), ()) == []
    assert scan(Dataset(columns=[], rows=[])) == []


def test_events_carry_counters_only() -> None:
    events: list[Mapping[str, str | int]] = []
    dataset = column_dataset("c1", ["a@example.com", "b@example.com", "c@example.com"])
    scan(dataset, on_event=events.append)
    assert [item["event"] for item in events] == [
        "scan_started",
        "column_flagged",
        "scan_completed",
    ]
    assert events[0]["columns"] == 1
    assert events[0]["rows"] == 3
    assert events[1]["column"] == "c1"
    assert events[1]["category"] == "email"
    assert events[1]["confidence_percent"] == 100
    assert events[1]["non_null_count"] == 3
    assert events[2]["findings"] == 1
    assert "example.com" not in json.dumps(events)


def test_failing_callback_does_not_abort_the_scan(caplog: pytest.LogCaptureFixture) -> None:
    def boom(payload: Mapping[str, str | int]) -> None:
        raise RuntimeError(SENTINEL)

    dataset = column_dataset("c1", ["a@example.com", "b@example.com"])
    with caplog.at_level(logging.WARNING, logger="pii_scan_datasets.scanner"):
        findings = scan(dataset, on_event=boom)
    assert len(findings) == 1
    assert "on_event" in caplog.text
    assert SENTINEL not in caplog.text


# ----------------------------------------------------------------------------- reader


def test_read_csv(tmp_path: Path) -> None:
    text = "id,email\n1,a@example.com\n2,\n3\n\n4,d@example.com,extra\n"
    dataset = read_dataset(write_text(tmp_path, "d.csv", text))
    assert dataset.columns == ["id", "email"]
    assert dataset.rows == [
        {"id": "1", "email": "a@example.com"},
        {"id": "2", "email": None},
        {"id": "3", "email": None},
        {"id": "4", "email": "d@example.com"},
    ]


def test_read_tsv_uppercase_suffix_and_blank_cells(tmp_path: Path) -> None:
    dataset = read_dataset(write_text(tmp_path, "d.TSV", "a\tb\nx\t  \n"))
    assert dataset.rows == [{"a": "x", "b": None}]


def test_read_csv_bom_blank_lines_and_header_only(tmp_path: Path) -> None:
    bom = tmp_path / "bom.csv"
    bom.write_bytes(b"\xef\xbb\xbfa,b\n1,2\n")
    assert read_dataset(bom).columns == ["a", "b"]
    lead = read_dataset(write_text(tmp_path, "lead.csv", "\n\nx\n1\n"))
    assert lead.columns == ["x"]
    header = read_dataset(write_text(tmp_path, "h.csv", "a,b\n"))
    assert header == Dataset(columns=["a", "b"], rows=[])


def test_read_empty_file(tmp_path: Path) -> None:
    assert read_dataset(write_text(tmp_path, "e.csv", "")) == Dataset(columns=[], rows=[])


def test_duplicate_and_empty_headers_are_made_unique(tmp_path: Path) -> None:
    dataset = read_dataset(write_text(tmp_path, "d.csv", "a, ,a,a\n1,2,3,4\n"))
    assert dataset.columns == ["a", "column_2", "a_2", "a_3"]
    assert dataset.rows[0]["a_3"] == "4"


def test_csv_sample_rows(tmp_path: Path) -> None:
    dataset = read_dataset(write_text(tmp_path, "d.csv", "a\n1\n2\n3\n4\n"), sample_rows=2)
    assert [row["a"] for row in dataset.rows] == ["1", "2"]


def test_max_columns(tmp_path: Path) -> None:
    csv_path = write_text(tmp_path, "d.csv", "a,b,c\n1,2,3\n")
    with pytest.raises(PiiScanError) as info:
        read_dataset(csv_path, max_columns=2)
    assert info.value.code == "too_large"
    assert read_dataset(csv_path, max_columns=3).columns == ["a", "b", "c"]
    jsonl_path = write_text(tmp_path, "d.jsonl", '{"a": 1, "b": 2, "c": 3}\n')
    with pytest.raises(PiiScanError) as info2:
        read_dataset(jsonl_path, max_columns=2)
    assert info2.value.code == "too_large"


def test_invalid_arguments(tmp_path: Path) -> None:
    path = write_text(tmp_path, "d.csv", "a\n1\n")
    with pytest.raises(ValueError, match="sample_rows"):
        read_dataset(path, sample_rows=0)
    with pytest.raises(ValueError, match="max_columns"):
        read_dataset(path, max_columns=0)


def test_unsupported_and_unreadable(tmp_path: Path) -> None:
    for name in ("data.xlsx", "noext"):
        with pytest.raises(PiiScanError) as info:
            read_dataset(tmp_path / name)
        assert info.value.code == "unsupported_format"
    (tmp_path / "dir.csv").mkdir()
    for name in ("missing.csv", "missing.jsonl", "dir.csv"):
        with pytest.raises(PiiScanError) as info2:
            read_dataset(tmp_path / name)
        assert info2.value.code == "unreadable"


def test_csv_invalid_utf8_is_unreadable(tmp_path: Path) -> None:
    path = tmp_path / "d.csv"
    path.write_bytes(b"a,b\n\xff\xfe,1\n")
    with pytest.raises(PiiScanError) as info:
        read_dataset(path)
    assert info.value.code == "unreadable"


def test_csv_oversized_field_is_too_large(tmp_path: Path) -> None:
    path = write_text(tmp_path, "d.csv", "c\n" + SENTINEL + "x" * 200_000 + "\n")
    with pytest.raises(PiiScanError) as info:
        read_dataset(path)
    assert info.value.code == "too_large"
    assert SENTINEL not in str(info.value)


def test_other_csv_errors_are_unreadable(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    path = write_text(tmp_path, "d.csv", "a\n1\n")

    def broken(*args: object, **kwargs: object) -> None:
        raise csv.Error("bad dialect")

    monkeypatch.setattr(csv, "reader", broken)
    with pytest.raises(PiiScanError) as info:
        read_dataset(path)
    assert info.value.code == "unreadable"


def test_jsonl_nested_object_is_flattened(tmp_path: Path) -> None:
    path = write_text(tmp_path, "d.jsonl", '{"user": {"email": "a@example.com"}}\n')
    dataset = read_dataset(path)
    assert dataset.columns == ["user.email"]
    assert dataset.rows == [{"user.email": "a@example.com"}]


def test_jsonl_value_kinds(tmp_path: Path) -> None:
    line = (
        '{"a": {"b": {"c": 1}}, "list": [1, {"x": 2}], "flag": true, "none": null, '
        '"empty": {}, "text": "  ", "s": "hi", "f": 1.5}\n'
    )
    dataset = read_dataset(write_text(tmp_path, "d.jsonl", line))
    assert dataset.columns == ["a.b.c", "list", "flag", "none", "empty", "text", "s", "f"]
    assert dataset.rows[0] == {
        "a.b.c": "1",
        "list": '[1,{"x":2}]',
        "flag": "true",
        "none": None,
        "empty": None,
        "text": None,
        "s": "hi",
        "f": "1.5",
    }


def test_jsonl_union_of_columns_blank_lines_crlf_and_bom(tmp_path: Path) -> None:
    text = '\n{"a": "1"}\r\n\r\n{"b": "2"}\r\n'
    dataset = read_dataset(write_text(tmp_path, "d.jsonl", text))
    assert dataset.columns == ["a", "b"]
    assert dataset.rows == [{"a": "1", "b": None}, {"a": None, "b": "2"}]
    bom = tmp_path / "bom.jsonl"
    bom.write_bytes(b'\xef\xbb\xbf{"a": "1"}\n')
    assert read_dataset(bom).rows == [{"a": "1"}]


@pytest.mark.parametrize("text", ["{not json}\n", "[1, 2]\n", '"text"\n', '}}}{"a":"1"}\n'])
def test_jsonl_invalid_lines_are_unreadable(tmp_path: Path, text: str) -> None:
    with pytest.raises(PiiScanError) as info:
        read_dataset(write_text(tmp_path, "d.jsonl", text))
    assert info.value.code == "unreadable"


def test_jsonl_invalid_utf8_is_unreadable(tmp_path: Path) -> None:
    path = tmp_path / "d.jsonl"
    path.write_bytes(b'{"a": "\xff"}\n')
    with pytest.raises(PiiScanError) as info:
        read_dataset(path)
    assert info.value.code == "unreadable"


def test_jsonl_sample_rows_stops_reading(tmp_path: Path) -> None:
    text = '\n{"a": "1"}\n\n{"a": "2"}\n{broken\n'
    path = write_text(tmp_path, "d.jsonl", text)
    dataset = read_dataset(path, sample_rows=2)
    assert [row["a"] for row in dataset.rows] == ["1", "2"]
    with pytest.raises(PiiScanError):
        read_dataset(path, sample_rows=3)


def test_only_the_first_two_rows_are_scanned(tmp_path: Path) -> None:
    lines = ['{"c": "a@example.com"}', '{"c": "b@example.com"}', '{"c": "nope"}'] * 2
    path = write_text(tmp_path, "d.jsonl", "\n".join(lines) + "\n")
    findings = scan(read_dataset(path, sample_rows=2))
    assert findings[0].non_null_count == 2
    assert findings[0].match_ratio == 1.0


def nested(levels: int) -> str:
    return '{"k": ' * levels + "1" + "}" * levels


def test_jsonl_depth_limit(tmp_path: Path) -> None:
    ok = read_dataset(write_text(tmp_path, "ok.jsonl", nested(32) + "\n"))
    assert ok.columns == [".".join(["k"] * 32)]
    with pytest.raises(PiiScanError) as info:
        read_dataset(write_text(tmp_path, "deep.jsonl", nested(33) + "\n"))
    assert info.value.code == "too_deep"


def test_jsonl_depth_counts_arrays_and_runs_before_parsing(tmp_path: Path) -> None:
    fine = '{"a": ' + "[" * 31 + "]" * 31 + "}\n"
    dataset = read_dataset(write_text(tmp_path, "ok.jsonl", fine))
    assert dataset.rows[0]["a"] == "[" * 31 + "]" * 31
    deep = '{"a": ' + "[" * 32 + "]" * 32 + "}\n"
    with pytest.raises(PiiScanError) as info:
        read_dataset(write_text(tmp_path, "deep.jsonl", deep))
    assert info.value.code == "too_deep"
    with pytest.raises(PiiScanError) as info2:
        read_dataset(write_text(tmp_path, "garbage.jsonl", "[" * 100 + "\n"))
    assert info2.value.code == "too_deep"


def test_brackets_inside_strings_are_not_nesting(tmp_path: Path) -> None:
    lines = [
        json.dumps({"a": "{" * 50}),
        json.dumps({"a": 'q"' + "[" * 40}),
        json.dumps({"a": "\\" + "[" * 40}),
    ]
    dataset = read_dataset(write_text(tmp_path, "d.jsonl", "\n".join(lines) + "\n"))
    assert [row["a"] for row in dataset.rows] == ["{" * 50, 'q"' + "[" * 40, "\\" + "[" * 40]


def test_jsonl_line_size_limit(tmp_path: Path) -> None:
    exact = '{"a":"' + "x" * (MAX_LINE - 8) + '"}'
    assert len(exact.encode()) == MAX_LINE
    assert len(read_dataset(write_text(tmp_path, "a.jsonl", exact + "\n")).rows) == 1
    assert len(read_dataset(write_text(tmp_path, "b.jsonl", exact + "\r\n")).rows) == 1
    over = '{"a":"' + "x" * (MAX_LINE - 7) + '"}'
    for name, text in (("c.jsonl", over + "\n"), ("d.jsonl", over), ("e.jsonl", over + "\r\n")):
        with pytest.raises(PiiScanError) as info:
            read_dataset(write_text(tmp_path, name, text))
        assert info.value.code == "too_large"


def test_jsonl_line_limit_counts_bytes_not_characters(tmp_path: Path) -> None:
    line = '{"a":"' + "\u00e9" * (MAX_LINE // 2) + '"}'
    assert len(line) < MAX_LINE < len(line.encode())
    with pytest.raises(PiiScanError) as info:
        read_dataset(write_text(tmp_path, "d.jsonl", line + "\n"))
    assert info.value.code == "too_large"


# ----------------------------------------------------------------------------- render


def sample_finding(column: str = "c1") -> ColumnFinding:
    return ColumnFinding(
        column=column,
        category="email",
        confidence=0.8,
        match_ratio=0.8,
        header_hint=False,
        non_null_count=10,
    )


def test_render_json() -> None:
    parsed = json.loads(render([sample_finding()], "json"))
    assert parsed == [
        {
            "column": "c1",
            "category": "email",
            "confidence": 0.8,
            "match_ratio": 0.8,
            "header_hint": False,
            "non_null_count": 10,
        }
    ]
    assert json.loads(render([], "json")) == []


def test_render_text() -> None:
    text = render([sample_finding()], "text")
    assert text == ("c1: email (confidence 0.80, match ratio 0.80, non-null 10, header hint no)")
    assert render([], "text") == "no personal data columns found"


def test_render_text_neutralises_control_characters_and_long_names() -> None:
    text = render([sample_finding("bad\x1b[31m\nname")], "text")
    assert "\x1b" not in text
    assert len(text.splitlines()) == 1
    long_text = render([sample_finding("a" * 500)], "text")
    assert "a" * 201 not in long_text
    assert "..." in long_text


def test_render_rejects_unknown_format() -> None:
    with pytest.raises(ValueError, match="fmt"):
        render([], "xml")  # type: ignore[arg-type]


def test_safe_text() -> None:
    assert safe_text("ok") == "ok"
    assert safe_text("a\tb") == "a?b"
    assert len(safe_text("x" * 1000)) == 200


# ----------------------------------------------------------------------------- errors


def test_error_has_stable_code_and_message() -> None:
    error = PiiScanError("too_deep", "nested")
    assert isinstance(error, Exception)
    assert error.code == "too_deep"
    assert error.message == "nested"
    assert str(error) == "nested"


def test_package_metadata_and_logging() -> None:
    assert pii_scan_datasets.__version__ == "0.1.0"
    handlers = logging.getLogger("pii_scan_datasets").handlers
    assert any(isinstance(item, logging.NullHandler) for item in handlers)


# ----------------------------------------------------------------------------- sentinels


@pytest.mark.parametrize("code", sorted(HOSTILE))
def test_errors_never_contain_cell_values(tmp_path: Path, code: str) -> None:
    path = write_text(tmp_path, "d.jsonl", HOSTILE[code] + "\n")
    with pytest.raises(PiiScanError) as info:
        read_dataset(path)
    assert info.value.code == code
    assert SENTINEL not in str(info.value)
    assert SENTINEL not in repr(info.value)


def sentinel_csv(tmp_path: Path) -> Path:
    rows = "\n".join(f"{SENTINEL.lower()}-{index}@example.com" for index in range(5))
    return write_text(tmp_path, "d.csv", "c1\n" + rows + "\n")


def test_sentinels_never_reach_output_or_events(tmp_path: Path) -> None:
    events: list[Mapping[str, str | int]] = []
    dataset = read_dataset(sentinel_csv(tmp_path))
    findings = scan(dataset, on_event=events.append)
    assert findings[0].category == "email"
    blob = render(findings, "text") + render(findings, "json") + json.dumps(events)
    assert "sentinel" not in blob.lower()
    assert repr(findings).lower().count("sentinel") == 0


# ----------------------------------------------------------------------------- cli


def test_cli_text_output_and_exit_codes(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    risky = write_text(tmp_path, "risky.csv", "c1\na@example.com\nb@example.com\n")
    clean = write_text(tmp_path, "clean.csv", "id\n1\n2\n")
    assert main([str(risky)]) == 0
    out = capsys.readouterr().out
    assert f"== {risky} ==" in out
    assert "c1: email" in out
    assert main([str(risky), "--fail-on-findings"]) == 1
    capsys.readouterr()
    assert main([str(clean), "--fail-on-findings"]) == 0
    assert "no personal data columns found" in capsys.readouterr().out
    assert main([str(clean)]) == 0


def test_cli_unreadable_path_exits_two(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    assert main([str(tmp_path / "missing.csv")]) == 2
    assert "unreadable" in capsys.readouterr().err
    assert main([str(tmp_path / "data.xlsx")]) == 2
    assert "unsupported_format" in capsys.readouterr().err


def test_cli_error_beats_findings_and_other_paths_still_print(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    risky = write_text(tmp_path, "risky.csv", "c1\na@example.com\nb@example.com\n")
    argv = [str(tmp_path / "missing.csv"), str(risky), "--fail-on-findings"]
    assert main(argv) == 2
    captured = capsys.readouterr()
    assert "c1: email" in captured.out
    assert "unreadable" in captured.err


def test_cli_json_format(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    risky = write_text(tmp_path, "risky.csv", "c1\na@example.com\nb@example.com\n")
    assert main([str(risky), "--format", "json"]) == 0
    parsed = json.loads(capsys.readouterr().out)
    assert parsed[0]["path"] == str(risky)
    assert parsed[0]["findings"][0]["category"] == "email"


def test_cli_threshold_and_sample_rows(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    emails = [f"u{index}@example.com" for index in range(11)]
    text = "c1\n" + "\n".join(emails + ["plain text"] * 9) + "\n"
    path = write_text(tmp_path, "d.csv", text)
    assert main([str(path), "--fail-on-findings"]) == 0
    assert main([str(path), "--threshold", "0.5", "--fail-on-findings"]) == 1
    capsys.readouterr()
    assert main([str(path), "--sample-rows", "2", "--fail-on-findings"]) == 1


def test_cli_rejects_bad_arguments(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    path = write_text(tmp_path, "d.csv", "a\n1\n")
    assert main([str(path), "--threshold", "1.5"]) == 2
    assert main([str(path), "--threshold", "nan"]) == 2
    assert main([str(path), "--sample-rows", "0"]) == 2
    assert main([str(path), "--threshold", "abc"]) == 2
    assert main([str(path), "--format", "xml"]) == 2
    assert main([]) == 2
    assert main(["--help"]) == 0
    assert "pii-scan-datasets" in capsys.readouterr().out


def test_cli_never_prints_cell_values(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    path = sentinel_csv(tmp_path)
    bad = write_text(tmp_path, "bad.jsonl", HOSTILE["unreadable"] + "\n")
    for fmt in ("text", "json"):
        assert main([str(path), str(bad), "--format", fmt]) == 2
        captured = capsys.readouterr()
        assert "sentinel" not in (captured.out + captured.err).lower()


def test_module_entry_point(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    path = write_text(tmp_path, "d.csv", "c1\na@example.com\nb@example.com\n")
    monkeypatch.setattr("sys.argv", ["pii-scan-datasets", str(path)])
    with warnings.catch_warnings():
        warnings.simplefilter("ignore")
        with pytest.raises(SystemExit) as info:
            runpy.run_module("pii_scan_datasets", run_name="__main__")
    assert info.value.code == 0
    assert "c1: email" in capsys.readouterr().out


def test_readme_usage_example_runs(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    import re

    readme = (Path(__file__).resolve().parent.parent / "README.md").read_text(encoding="utf-8")
    block = re.search(r"```python\n(.*?)```", readme, re.S)
    assert block is not None
    write_text(tmp_path, "data.csv", "email\na@example.com\nb@example.com\n")
    monkeypatch.chdir(tmp_path)
    exec(compile(block.group(1), "README.md", "exec"), {})  # noqa: S102
    assert "email" in capsys.readouterr().out
