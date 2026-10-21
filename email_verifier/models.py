from __future__ import annotations

from dataclasses import asdict, dataclass, field
from enum import StrEnum
from typing import Any


class VerificationStatus(StrEnum):
    VALID = "valid"
    INVALID = "invalid"
    RISKY = "risky"
    UNKNOWN = "unknown"
    UNREACHABLE = "unreachable"


class EvidenceLevel(StrEnum):
    NONE = "none"
    SYNTAX = "syntax"
    DOMAIN = "domain"
    SMTP = "smtp"
    AMBIGUOUS = "ambiguous"


@dataclass(slots=True)
class SyntaxResult:
    valid: bool
    normalized_email: str | None = None
    local_part: str | None = None
    domain: str | None = None
    internationalized: bool = False
    reason_code: str | None = None
    message: str | None = None


@dataclass(slots=True)
class DnsResult:
    domain: str
    outcome: str
    mx_records: list[str] = field(default_factory=list)
    fallback_addresses: list[str] = field(default_factory=list)
    ttl_seconds: int | None = None
    error_code: str | None = None
    message: str | None = None

    @property
    def has_mail_routing(self) -> bool:
        return bool(self.mx_records or self.fallback_addresses)


@dataclass(slots=True)
class SmtpResult:
    outcome: str
    response_code: int | None = None
    response_message: str | None = None
    mx_host: str | None = None
    attempted_hosts: list[str] = field(default_factory=list)
    tls_used: bool = False


@dataclass(slots=True)
class CatchAllResult:
    status: str = "not_checked"
    probe_domain: str | None = None
    response: str | None = None


@dataclass(slots=True)
class VerificationResult:
    original_email: str
    normalized_email: str | None
    status: VerificationStatus
    syntax: SyntaxResult
    domain: DnsResult | None = None
    smtp: SmtpResult | None = None
    catch_all: CatchAllResult = field(default_factory=CatchAllResult)
    disposable: bool = False
    role_based: bool = False
    reason_codes: list[str] = field(default_factory=list)
    stages_completed: list[str] = field(default_factory=list)
    evidence_level: EvidenceLevel = EvidenceLevel.NONE
    duration_ms: float = 0.0
    timestamp: str = ""

    def to_dict(self) -> dict[str, Any]:
        return _serialize(asdict(self))


def _serialize(value: Any) -> Any:
    if isinstance(value, StrEnum):
        return value.value
    if isinstance(value, dict):
        return {key: _serialize(item) for key, item in value.items()}
    if isinstance(value, list):
        return [_serialize(item) for item in value]
    return value
