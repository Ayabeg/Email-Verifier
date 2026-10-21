from __future__ import annotations

import threading
import time
from collections import OrderedDict
from dataclasses import dataclass
from typing import Protocol

try:
    import dns.exception
    import dns.resolver
except ImportError:  # pragma: no cover - exercised when optional runtime is absent
    dns = None  # type: ignore[assignment]

from .models import DnsResult


class ResolverUnavailable(RuntimeError):
    pass


class DomainResolver(Protocol):
    def lookup(self, domain: str) -> DnsResult: ...


@dataclass(slots=True)
class _CacheEntry:
    expires_at: float
    result: DnsResult


class TtlDnsCache:
    def __init__(self, max_entries: int = 4096, default_ttl: int = 300) -> None:
        self.max_entries = max(1, max_entries)
        self.default_ttl = max(1, default_ttl)
        self._entries: OrderedDict[str, _CacheEntry] = OrderedDict()
        self._lock = threading.RLock()

    def get(self, key: str) -> DnsResult | None:
        with self._lock:
            entry = self._entries.get(key)
            if entry is None:
                return None
            if entry.expires_at <= time.monotonic():
                self._entries.pop(key, None)
                return None
            self._entries.move_to_end(key)
            return entry.result

    def put(self, key: str, result: DnsResult) -> None:
        ttl = max(1, result.ttl_seconds or self.default_ttl)
        with self._lock:
            self._entries[key] = _CacheEntry(time.monotonic() + ttl, result)
            self._entries.move_to_end(key)
            while len(self._entries) > self.max_entries:
                self._entries.popitem(last=False)


class DnsPythonResolver:
    """MX-first resolver with explicit temporary and permanent outcomes."""

    def __init__(self, *, timeout: float = 3.0, cache: TtlDnsCache | None = None) -> None:
        self.timeout = max(0.1, timeout)
        self.cache = cache or TtlDnsCache()
        self._locks: dict[str, threading.Lock] = {}
        self._locks_guard = threading.Lock()

    def lookup(self, domain: str) -> DnsResult:
        cached = self.cache.get(domain)
        if cached is not None:
            return cached
        with self._locks_guard:
            lock = self._locks.setdefault(domain, threading.Lock())
        with lock:
            cached = self.cache.get(domain)
            if cached is not None:
                return cached
            result = self._lookup_uncached(domain)
            self.cache.put(domain, result)
            return result

    def _lookup_uncached(self, domain: str) -> DnsResult:
        if dns is None:
            raise ResolverUnavailable("dnspython is required for DNS verification")
        resolver = dns.resolver.Resolver()
        resolver.timeout = self.timeout
        resolver.lifetime = self.timeout
        try:
            answers = resolver.resolve(domain, "MX", raise_on_no_answer=False)
            ttl = int(getattr(answers.rrset, "ttl", 0) or 0) or None
            mx_records = [
                (int(getattr(answer, "preference", 0)), str(answer.exchange).rstrip(".").lower())
                for answer in answers
                if answer.exchange
            ]
            mx_records = [host for _, host in sorted(mx_records)]
            if mx_records:
                return DnsResult(
                    domain=domain, outcome="mx", mx_records=mx_records, ttl_seconds=ttl
                )
            fallback, fallback_error = self._fallback_addresses(resolver, domain)
            if fallback_error:
                return DnsResult(domain=domain, outcome=fallback_error, error_code=fallback_error)
            if fallback:
                return DnsResult(
                    domain=domain,
                    outcome="implicit_mx",
                    fallback_addresses=fallback,
                    ttl_seconds=ttl,
                )
            return DnsResult(
                domain=domain, outcome="no_mail_routing", ttl_seconds=ttl, error_code="no_mx"
            )
        except dns.resolver.NXDOMAIN:
            return DnsResult(
                domain=domain,
                outcome="nxdomain",
                error_code="nxdomain",
                message="domain does not exist",
            )
        except dns.resolver.NoNameservers as exc:
            return DnsResult(
                domain=domain, outcome="servfail", error_code="servfail", message=str(exc)
            )
        except (dns.exception.Timeout, TimeoutError) as exc:
            return DnsResult(
                domain=domain, outcome="timeout", error_code="timeout", message=str(exc)
            )
        except dns.resolver.NoAnswer:
            fallback, fallback_error = self._fallback_addresses(resolver, domain)
            if fallback_error:
                return DnsResult(domain=domain, outcome=fallback_error, error_code=fallback_error)
            outcome = "implicit_mx" if fallback else "no_mail_routing"
            return DnsResult(
                domain=domain,
                outcome=outcome,
                fallback_addresses=fallback,
                error_code=None if fallback else "no_mx",
            )
        except OSError as exc:
            return DnsResult(
                domain=domain,
                outcome="resolver_error",
                error_code="resolver_error",
                message=str(exc),
            )

    def _fallback_addresses(self, resolver: object, domain: str) -> tuple[list[str], str | None]:
        addresses: list[str] = []
        temporary_error: str | None = None
        for record_type in ("A", "AAAA"):
            try:
                answers = resolver.resolve(domain, record_type, raise_on_no_answer=False)  # type: ignore[attr-defined]
                addresses.extend(str(answer) for answer in answers)
            except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN):  # type: ignore[union-attr]
                continue
            except dns.exception.Timeout:  # type: ignore[union-attr]
                temporary_error = "timeout"
            except dns.resolver.NoNameservers:  # type: ignore[union-attr]
                temporary_error = "servfail"
        return list(dict.fromkeys(addresses)), temporary_error


class StaticResolver:
    """Small deterministic resolver useful for applications and tests."""

    def __init__(self, results: dict[str, DnsResult]) -> None:
        self.results = results
        self.calls: list[str] = []

    def lookup(self, domain: str) -> DnsResult:
        self.calls.append(domain)
        return self.results.get(
            domain, DnsResult(domain=domain, outcome="nxdomain", error_code="nxdomain")
        )
