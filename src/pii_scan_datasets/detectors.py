"""Checksum-validated detectors for columns that hold personal data.

Every detector matches the whole trimmed cell, never a substring. The IBAN length table in
``IBAN_LENGTHS`` comes from the SWIFT IBAN Registry (checked 2026-11-05).
"""

from __future__ import annotations

import ipaddress
import re
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass
from datetime import date
from types import MappingProxyType

_IBAN_TABLE = (
    "AD=24 AT=20 BE=16 BG=22 CH=21 CY=28 CZ=24 DE=22 DK=18 EE=20 ES=24 FI=18 FR=27 GB=22 "
    "GI=23 GR=27 HR=21 HU=28 IE=22 IS=26 IT=27 LI=21 LT=20 LU=20 LV=21 MC=27 MT=31 NL=18 "
    "NO=15 PL=28 PT=25 RO=24 SE=24 SI=19 SK=24 SM=27 VA=22"
)

IBAN_LENGTHS: Mapping[str, int] = MappingProxyType(
    {item[:2]: int(item[3:]) for item in _IBAN_TABLE.split()}
)
"""IBAN length per country (ISO 13616). Source: SWIFT IBAN Registry, checked 2026-11-05."""

_MAX_EMAIL_CHARS = 254
_DNI_LETTERS = "TRWAGMYFPDXBNJZSQVHLCKE"
_ISO_DATE = re.compile(r"[0-9]{4}-[0-9]{2}-[0-9]{2}")
_THOUSANDS = re.compile(r"[0-9]{1,3}(?:[.][0-9]{3})+")
_PHONE_CHARS = re.compile(r"\+?[0-9 .()\-]+")
_PHONE_SEPARATORS = " .-()"
_EMAIL = re.compile(r"[^@\s]{1,64}@[^@\s]+\.[^@\s]{2,}")
_DIGITS = re.compile(r"[0-9]+")
_IBAN_SHAPE = re.compile(r"[A-Za-z]{2}[0-9]{2}[A-Za-z0-9]+")
_SSN = re.compile(r"([0-9]{3})-([0-9]{2})-([0-9]{4})")
_DNI = re.compile(r"([0-9]{8}|[XYZ][0-9]{7})([A-Z])", re.ASCII | re.IGNORECASE)
_HEADER_SEPARATORS = re.compile(r"[\s.\-]+")


@dataclass(frozen=True)
class DetectorContext:
    """Per-column information handed to a detector.

    ``header_hint`` is true when the column header hints at the detector's category and
    ``iban_lengths`` is the country length table in force.
    """

    header_hint: bool
    iban_lengths: Mapping[str, int]


@dataclass(frozen=True)
class Detector:
    """A column detector.

    ``matches`` receives one trimmed, non-empty cell and the column context and returns true when
    the whole cell is a valid value of the detector's kind.
    """

    name: str
    category: str
    matches: Callable[[str, DetectorContext], bool]
    header_hints: tuple[str, ...] = ()


def header_tokens(header: str) -> list[str]:
    """Split a header into lower-case tokens; spaces, dashes, dots and underscores separate."""
    unified = _HEADER_SEPARATORS.sub("_", header.lower())
    return [token for token in unified.split("_") if token]


def header_matches(header: str, hints: Sequence[str]) -> bool:
    """Return true when a hint (for example ``first_name``) occurs as whole header tokens."""
    tokens = header_tokens(header)
    for hint in hints:
        wanted = hint.split("_")
        size = len(wanted)
        for start in range(len(tokens) - size + 1):
            end = start + size
            if tokens[start:end] == wanted:
                return True
    return False


def _is_email(value: str, context: DetectorContext) -> bool:
    # Not RFC 5322. The length cap also bounds regex backtracking.
    return len(value) <= _MAX_EMAIL_CHARS and _EMAIL.fullmatch(value) is not None


def _is_phone(value: str, context: DetectorContext) -> bool:
    if _ISO_DATE.fullmatch(value) or _THOUSANDS.fullmatch(value):
        return False
    if _PHONE_CHARS.fullmatch(value) is None:
        return False
    digit_count = sum(1 for char in value if char.isdigit())
    if not 7 <= digit_count <= 15:
        return False
    explicit = value.startswith("+") or any(char in _PHONE_SEPARATORS for char in value)
    return explicit or context.header_hint


def _luhn_ok(digits: str) -> bool:
    total = 0
    for index, char in enumerate(reversed(digits)):
        number = int(char)
        if index % 2 == 1:
            number *= 2
            if number > 9:
                number -= 9
        total += number
    return total % 10 == 0


def _is_card(value: str, context: DetectorContext) -> bool:
    digits = value.replace(" ", "").replace("-", "")
    if not 13 <= len(digits) <= 19 or _DIGITS.fullmatch(digits) is None:
        return False
    return _luhn_ok(digits)


def _is_iban(value: str, context: DetectorContext) -> bool:
    """Check ISO 13616 shape, the country length and the ISO 7064 mod-97-10 checksum."""
    compact = value.replace(" ", "")
    if _IBAN_SHAPE.fullmatch(compact) is None:
        return False
    compact = compact.upper()
    if context.iban_lengths.get(compact[:2]) != len(compact):
        return False
    rearranged = compact[4:] + compact[:4]
    number = int("".join(str(int(char, 36)) for char in rearranged))
    return number % 97 == 1


def _is_ip(value: str, context: DetectorContext) -> bool:
    try:
        ipaddress.ip_address(value)
    except ValueError:
        return False
    return True


def _is_ssn(value: str, context: DetectorContext) -> bool:
    found = _SSN.fullmatch(value)
    if found is None:
        return False
    area, group, serial = found.groups()
    if area in ("000", "666") or area.startswith("9"):
        return False
    return group != "00" and serial != "0000"


def _is_dni_nie(value: str, context: DetectorContext) -> bool:
    found = _DNI.fullmatch(value)
    if found is None:
        return False
    body, letter = found.groups()
    if body[0] in "xyzXYZ":
        body = str("XYZ".index(body[0].upper())) + body[1:]
    return _DNI_LETTERS[int(body) % 23] == letter.upper()


def _is_birth_date(value: str, context: DetectorContext) -> bool:
    if not context.header_hint or _ISO_DATE.fullmatch(value) is None:
        return False
    try:
        date.fromisoformat(value)
    except ValueError:
        return False
    return True


def _hint_only(value: str, context: DetectorContext) -> bool:
    return False


DEFAULT_DETECTORS: tuple[Detector, ...] = (
    Detector(
        name="email",
        category="email",
        matches=_is_email,
        header_hints=("email", "correo"),
    ),
    Detector(
        name="phone",
        category="phone",
        matches=_is_phone,
        header_hints=("phone", "telefono", "movil"),
    ),
    Detector(
        name="payment_card",
        category="payment_card",
        matches=_is_card,
        header_hints=("card", "tarjeta"),
    ),
    Detector(
        name="iban",
        category="iban",
        matches=_is_iban,
        header_hints=("iban",),
    ),
    Detector(
        name="ip_address",
        category="ip_address",
        matches=_is_ip,
        header_hints=("ip",),
    ),
    Detector(
        name="us_ssn",
        category="national_id",
        matches=_is_ssn,
        header_hints=("ssn",),
    ),
    Detector(
        name="es_dni_nie",
        category="national_id",
        matches=_is_dni_nie,
        header_hints=("dni", "nie", "nif", "cedula"),
    ),
    Detector(
        name="date_of_birth",
        category="date_of_birth",
        matches=_is_birth_date,
        header_hints=("birth", "dob", "fecha_nacimiento"),
    ),
    Detector(
        name="person_name",
        category="person_name",
        matches=_hint_only,
        header_hints=("name", "first_name", "last_name", "nombre", "apellido"),
    ),
    Detector(
        name="address",
        category="address",
        matches=_hint_only,
        header_hints=("address", "direccion"),
    ),
)
"""The ten built-in detectors."""
