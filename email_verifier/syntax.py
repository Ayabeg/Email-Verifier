from __future__ import annotations

import re

from .models import SyntaxResult

_ASCII_ATEXT = frozenset(
    "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!#$%&'*+-/=?^_`{|}~"
)
_DOMAIN_LABEL = re.compile(r"^[A-Za-z0-9\-]+$")


def parse_email(value: str, *, allow_unicode_local: bool = True) -> SyntaxResult:
    """Validate and normalize an address without changing the local part.

    This deliberately supports dot-atom and quoted local parts plus IDN domains.
    Comments, obsolete syntax, domain literals, and display names are rejected so
    callers do not accidentally verify a different address than the user entered.
    """
    if not isinstance(value, str):
        return _invalid("syntax.not_string", "email must be a string")
    candidate = value.strip()
    if not candidate:
        return _invalid("syntax.empty", "email is empty")
    if any(ord(char) < 32 or ord(char) == 127 for char in candidate):
        return _invalid("syntax.control_character", "email contains a control character")
    split = _split_at(candidate)
    if split is None:
        return _invalid("syntax.missing_at", "email must contain exactly one unquoted @")
    local, raw_domain = split
    if not local or not raw_domain:
        return _invalid("syntax.missing_component", "email must contain a local part and domain")
    domain = _normalize_domain(raw_domain)
    if domain is None:
        return _invalid("syntax.invalid_domain", "domain is not a valid DNS name")
    if not _valid_local(local, allow_unicode_local=allow_unicode_local):
        return _invalid("syntax.invalid_local_part", "local part is not supported")
    if len(local.encode("utf-8")) > 64:
        return _invalid("syntax.local_part_too_long", "local part exceeds 64 UTF-8 bytes")
    normalized = f"{local}@{domain}"
    if len(normalized.encode("utf-8")) > 254:
        return _invalid("syntax.address_too_long", "address exceeds 254 UTF-8 bytes")
    return SyntaxResult(
        valid=True,
        normalized_email=normalized,
        local_part=local,
        domain=domain,
        internationalized=any(ord(char) > 127 for char in candidate),
    )


def _split_at(value: str) -> tuple[str, str] | None:
    quoted = False
    escaped = False
    positions: list[int] = []
    for index, char in enumerate(value):
        if escaped:
            escaped = False
            continue
        if char == "\\" and quoted:
            escaped = True
            continue
        if char == '"':
            quoted = not quoted
        elif char == "@" and not quoted:
            positions.append(index)
    if quoted or len(positions) != 1:
        return None
    index = positions[0]
    return value[:index], value[index + 1 :]


def _valid_local(local: str, *, allow_unicode_local: bool) -> bool:
    if local.startswith('"') or local.endswith('"'):
        if not (local.startswith('"') and local.endswith('"')) or len(local) < 2:
            return False
        escaped = False
        for char in local[1:-1]:
            if ord(char) < 32 or ord(char) == 127:
                return False
            if escaped:
                escaped = False
            elif char == "\\":
                escaped = True
            elif char == '"':
                return False
        return not escaped
    if '"' in local or any(char.isspace() for char in local):
        return False
    if local.startswith(".") or local.endswith(".") or ".." in local:
        return False
    for char in local:
        if char in _ASCII_ATEXT:
            continue
        if ord(char) > 127 and allow_unicode_local and not char.isspace():
            continue
        return False
    return True


def _normalize_domain(domain: str) -> str | None:
    if domain.startswith("[") or domain.endswith("]"):
        return None
    if any(char.isspace() for char in domain) or domain.endswith("."):
        return None
    try:
        ascii_domain = domain.encode("idna").decode("ascii").lower()
    except UnicodeError:
        return None
    if len(ascii_domain) > 253 or not ascii_domain or ".." in ascii_domain:
        return None
    labels = ascii_domain.split(".")
    if any(not label or len(label) > 63 for label in labels):
        return None
    for label in labels:
        if label.startswith("-") or label.endswith("-") or not _DOMAIN_LABEL.fullmatch(label):
            return None
    return ascii_domain


def _invalid(code: str, message: str) -> SyntaxResult:
    return SyntaxResult(valid=False, reason_code=code, message=message)
