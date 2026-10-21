from __future__ import annotations

import secrets
import time
from dataclasses import dataclass
from datetime import UTC, datetime

from .classifiers import ClassifierData
from .dns import DnsPythonResolver, DomainResolver, ResolverUnavailable, TtlDnsCache
from .models import (
    CatchAllResult,
    DnsResult,
    EvidenceLevel,
    SmtpResult,
    VerificationResult,
    VerificationStatus,
)
from .smtp import SmtpConfig, SmtpVerifier
from .syntax import parse_email


@dataclass(slots=True)
class VerificationConfig:
    dns_enabled: bool = True
    smtp_enabled: bool = False
    catch_all_enabled: bool = False
    sender: str = "verify@example.com"
    dns_timeout: float = 3.0
    smtp_timeout: float = 8.0
    smtp_tls_mode: str = "opportunistic"
    max_mx_hosts: int = 3
    max_catch_all_probes: int = 1
    classifier_data: ClassifierData | None = None
    resolver: DomainResolver | None = None
    smtp_verifier: SmtpVerifier | None = None
    cache_entries: int = 4096
    cache_ttl_seconds: int = 300


class VerificationEngine:
    def __init__(self, config: VerificationConfig | None = None) -> None:
        self.config = config or VerificationConfig()
        self.classifiers = self.config.classifier_data or ClassifierData.load()
        self._cache = TtlDnsCache(self.config.cache_entries, self.config.cache_ttl_seconds)
        self.resolver = self.config.resolver or DnsPythonResolver(
            timeout=self.config.dns_timeout, cache=self._cache
        )
        self.smtp = self.config.smtp_verifier or SmtpVerifier(
            SmtpConfig(
                sender=self.config.sender,
                timeout=self.config.smtp_timeout,
                tls_mode=self.config.smtp_tls_mode,
                max_hosts=self.config.max_mx_hosts,
            )
        )

    def verify(self, email: str) -> VerificationResult:
        started = time.perf_counter()
        syntax = parse_email(email)
        stages = ["syntax"]
        reasons: list[str] = []
        if not syntax.valid:
            reasons.append(syntax.reason_code or "syntax.invalid")
            return self._result(
                email,
                syntax,
                VerificationStatus.INVALID,
                None,
                None,
                CatchAllResult(),
                False,
                False,
                reasons,
                stages,
                EvidenceLevel.SYNTAX,
                started,
            )

        assert (
            syntax.domain is not None
            and syntax.local_part is not None
            and syntax.normalized_email is not None
        )
        disposable = self.classifiers.is_disposable(syntax.domain)
        role_based = self.classifiers.is_role_based(syntax.local_part)
        if disposable:
            reasons.append("classification.disposable_domain")
        if role_based:
            reasons.append("classification.role_based")

        domain: DnsResult | None = None
        if self.config.dns_enabled:
            stages.append("dns")
            try:
                domain = self.resolver.lookup(syntax.domain)
            except ResolverUnavailable:
                reasons.append("dns.unavailable")
                return self._result(
                    email,
                    syntax,
                    VerificationStatus.UNREACHABLE,
                    None,
                    None,
                    CatchAllResult(),
                    disposable,
                    role_based,
                    reasons,
                    stages,
                    EvidenceLevel.SYNTAX,
                    started,
                )
            if domain.outcome == "nxdomain":
                reasons.append("domain.nxdomain")
                return self._result(
                    email,
                    syntax,
                    VerificationStatus.INVALID,
                    domain,
                    None,
                    CatchAllResult(),
                    disposable,
                    role_based,
                    reasons,
                    stages,
                    EvidenceLevel.DOMAIN,
                    started,
                )
            if domain.outcome in {"timeout", "servfail", "resolver_error"}:
                reasons.append(f"dns.{domain.outcome}")
                return self._result(
                    email,
                    syntax,
                    VerificationStatus.UNREACHABLE,
                    domain,
                    None,
                    CatchAllResult(),
                    disposable,
                    role_based,
                    reasons,
                    stages,
                    EvidenceLevel.SYNTAX,
                    started,
                )
            if not domain.has_mail_routing:
                reasons.append("domain.no_mail_routing")
                return self._result(
                    email,
                    syntax,
                    VerificationStatus.INVALID,
                    domain,
                    None,
                    CatchAllResult(),
                    disposable,
                    role_based,
                    reasons,
                    stages,
                    EvidenceLevel.DOMAIN,
                    started,
                )
        else:
            reasons.append("dns.disabled")

        smtp_result: SmtpResult | None = None
        catch_all = CatchAllResult()
        if self.config.smtp_enabled:
            stages.append("smtp")
            hosts = list(domain.mx_records) if domain else []
            if not hosts and domain:
                hosts = [syntax.domain]
            smtp_result = self.smtp.verify(syntax.normalized_email, hosts)
            if smtp_result.outcome == "rejected":
                reasons.append("smtp.permanent_rejection")
                return self._result(
                    email,
                    syntax,
                    VerificationStatus.INVALID,
                    domain,
                    smtp_result,
                    catch_all,
                    disposable,
                    role_based,
                    reasons,
                    stages,
                    EvidenceLevel.SMTP,
                    started,
                )
            if smtp_result.outcome in {"temporary", "unreachable", "unsupported"}:
                reasons.append(f"smtp.{smtp_result.outcome}")
            elif smtp_result.outcome == "ambiguous":
                reasons.append("smtp.ambiguous_acceptance")
            if (
                self.config.catch_all_enabled
                and smtp_result.outcome in {"accepted", "ambiguous"}
                and self.config.max_catch_all_probes > 0
            ):
                stages.append("catch_all")
                catch_all = self._check_catch_all(
                    syntax.domain, smtp_result, syntax.normalized_email
                )
                if catch_all.status == "detected":
                    reasons.append("catch_all.detected")
                elif catch_all.status == "inconclusive":
                    reasons.append("catch_all.inconclusive")

        if (
            catch_all.status == "detected"
            or disposable
            or role_based
            or (smtp_result and smtp_result.outcome == "ambiguous")
        ):
            status = VerificationStatus.RISKY
            evidence = (
                EvidenceLevel.AMBIGUOUS
                if smtp_result and smtp_result.outcome == "ambiguous"
                else EvidenceLevel.DOMAIN
            )
        elif smtp_result and smtp_result.outcome == "accepted":
            status = VerificationStatus.VALID
            evidence = EvidenceLevel.SMTP
        elif smtp_result and smtp_result.outcome in {"temporary", "unreachable", "unsupported"}:
            status = (
                VerificationStatus.UNREACHABLE
                if smtp_result.outcome == "unreachable"
                else VerificationStatus.UNKNOWN
            )
            evidence = EvidenceLevel.DOMAIN
        else:
            reasons.append("mailbox.not_checked")
            status = VerificationStatus.UNKNOWN
            evidence = EvidenceLevel.DOMAIN if domain else EvidenceLevel.SYNTAX
        return self._result(
            email,
            syntax,
            status,
            domain,
            smtp_result,
            catch_all,
            disposable,
            role_based,
            reasons,
            stages,
            evidence,
            started,
        )

    def _check_catch_all(self, domain: str, baseline: SmtpResult, original: str) -> CatchAllResult:
        probe = f"__ev_{secrets.token_hex(12)}@{domain}"
        hosts = baseline.attempted_hosts[:1] or (
            [baseline.mx_host] if baseline.mx_host else [domain]
        )
        response = self.smtp.verify(probe, [host for host in hosts if host])
        if response.outcome in {"accepted", "ambiguous"}:
            return CatchAllResult(status="detected", probe_domain=probe, response=response.outcome)
        if response.outcome == "rejected":
            return CatchAllResult(
                status="not_detected", probe_domain=probe, response=response.outcome
            )
        return CatchAllResult(status="inconclusive", probe_domain=probe, response=response.outcome)

    @staticmethod
    def _result(
        email: str,
        syntax,
        status,
        domain,
        smtp,
        catch_all,
        disposable,
        role_based,
        reasons,
        stages,
        evidence,
        started,
    ):
        return VerificationResult(
            original_email=email,
            normalized_email=syntax.normalized_email,
            status=status,
            syntax=syntax,
            domain=domain,
            smtp=smtp,
            catch_all=catch_all,
            disposable=disposable,
            role_based=role_based,
            reason_codes=list(dict.fromkeys(reasons)),
            stages_completed=stages,
            evidence_level=evidence,
            duration_ms=round((time.perf_counter() - started) * 1000, 3),
            timestamp=datetime.now(UTC).isoformat(),
        )
