from __future__ import annotations

import ipaddress
import smtplib
import socket
import threading
import time
from dataclasses import dataclass

from .models import SmtpResult


@dataclass(frozen=True, slots=True)
class SmtpConfig:
    sender: str
    timeout: float = 4.0
    port: int = 25
    tls_mode: str = "opportunistic"  # disabled, opportunistic, required
    helo_name: str = "email-verifier.local"
    max_hosts: int = 2
    max_total_seconds: float = 8.0


class SmtpVerifier:
    def __init__(self, config: SmtpConfig) -> None:
        if config.tls_mode not in {"disabled", "opportunistic", "required"}:
            raise ValueError("tls_mode must be disabled, opportunistic, or required")
        if config.timeout <= 0 or config.max_total_seconds <= 0:
            raise ValueError("SMTP timeouts must be positive")
        if config.max_hosts < 1:
            raise ValueError("max_hosts must be at least 1")
        self.config = config

    def verify(self, recipient: str, hosts: list[str]) -> SmtpResult:
        attempted: list[str] = []
        last_temporary: SmtpResult | None = None
        last_unsupported: SmtpResult | None = None
        deadline = time.monotonic() + self.config.max_total_seconds
        for host in hosts[: max(1, self.config.max_hosts)]:
            if time.monotonic() >= deadline:
                break
            attempted.append(host)
            result = self._verify_host(recipient, host, attempted, deadline)
            if result.outcome in {"accepted", "rejected", "ambiguous"}:
                return result
            if result.outcome == "temporary":
                last_temporary = result
            elif result.outcome == "unsupported":
                last_unsupported = result
        if last_temporary is not None:
            last_temporary.attempted_hosts = attempted
            return last_temporary
        if last_unsupported is not None:
            last_unsupported.attempted_hosts = attempted
            return last_unsupported
        return SmtpResult(
            outcome="unreachable",
            mx_host=attempted[-1] if attempted else None,
            attempted_hosts=attempted,
            response_message="SMTP verification time budget exceeded",
        )

    def _verify_host(
        self, recipient: str, host: str, attempted: list[str], deadline: float
    ) -> SmtpResult:
        client: smtplib.SMTP | None = None
        tls_used = False
        try:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                return SmtpResult(
                    outcome="unreachable",
                    response_message="SMTP verification time budget exceeded",
                    mx_host=host,
                    attempted_hosts=attempted,
                )
            public_ip = _select_public_address(
                host, self.config.port, timeout=min(self.config.timeout, remaining)
            )
            if public_ip is None:
                return SmtpResult(
                    outcome="unsupported",
                    response_message="MX target did not resolve to a public address",
                    mx_host=host,
                    attempted_hosts=attempted,
                )
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                return SmtpResult(
                    outcome="unreachable",
                    response_message="SMTP verification time budget exceeded",
                    mx_host=host,
                    attempted_hosts=attempted,
                )
            client = smtplib.SMTP(timeout=min(self.config.timeout, remaining))
            client.connect(public_ip, self.config.port)
            client._host = host  # type: ignore[attr-defined]  # preserve MX name for STARTTLS SNI
            client.ehlo(self.config.helo_name)
            if self.config.tls_mode != "disabled" and client.has_extn("starttls"):
                client.starttls()
                client.ehlo(self.config.helo_name)
                tls_used = True
            elif self.config.tls_mode == "required":
                return SmtpResult(outcome="unsupported", mx_host=host, attempted_hosts=attempted)
            requires_smtputf8 = any(ord(char) > 127 for char in recipient + self.config.sender)
            if requires_smtputf8 and not client.has_extn("smtputf8"):
                return SmtpResult(
                    outcome="unsupported",
                    response_message="server does not advertise SMTPUTF8",
                    mx_host=host,
                    attempted_hosts=attempted,
                    tls_used=tls_used,
                )
            mail_options = ["SMTPUTF8"] if requires_smtputf8 else []
            mail_code, mail_message = client.mail(self.config.sender, options=mail_options)
            if not 200 <= mail_code < 300:
                return SmtpResult(
                    outcome="temporary" if 400 <= mail_code < 500 else "unsupported",
                    response_code=mail_code,
                    response_message=_decode(mail_message),
                    mx_host=host,
                    attempted_hosts=attempted,
                    tls_used=tls_used,
                )
            code, message = client.rcpt(recipient)
            return SmtpResult(
                outcome=_response_outcome(code),
                response_code=code,
                response_message=_decode(message),
                mx_host=host,
                attempted_hosts=attempted,
                tls_used=tls_used,
            )
        except smtplib.SMTPResponseException as exc:
            return SmtpResult(
                outcome=_response_outcome(exc.smtp_code),
                response_code=exc.smtp_code,
                response_message=_decode(exc.smtp_error),
                mx_host=host,
                attempted_hosts=attempted,
                tls_used=tls_used,
            )
        except (smtplib.SMTPException, socket.timeout, TimeoutError, OSError, UnicodeError) as exc:
            return SmtpResult(
                outcome="unreachable",
                response_message=str(exc),
                mx_host=host,
                attempted_hosts=attempted,
            )
        finally:
            if client is not None:
                try:
                    client.quit()
                except (smtplib.SMTPException, OSError):
                    client.close()


def _response_outcome(code: int) -> str:
    if code == 252:
        return "ambiguous"
    if 200 <= code < 300:
        return "accepted"
    if 400 <= code < 500:
        return "temporary"
    if 500 <= code < 600:
        return "rejected"
    return "ambiguous"


def _select_public_address(host: str, port: int, timeout: float = 2.0) -> str | None:
    """Resolve a host without allowing a stuck system resolver to block a request."""
    addresses: list[tuple] = []
    completed = threading.Event()

    def resolve() -> None:
        try:
            addresses.extend(socket.getaddrinfo(host, port, type=socket.SOCK_STREAM))
        except (OSError, socket.gaierror):
            pass
        finally:
            completed.set()

    threading.Thread(target=resolve, name="smtp-address-lookup", daemon=True).start()
    if not completed.wait(max(0.1, timeout)):
        return None
    for address in addresses:
        candidate = address[4][0]
        try:
            if ipaddress.ip_address(candidate).is_global:
                return candidate
        except ValueError:
            continue
    return None


def _decode(value: bytes | str | None) -> str | None:
    if value is None:
        return None
    if isinstance(value, bytes):
        return value.decode("utf-8", errors="replace")[:500]
    return str(value)[:500]
