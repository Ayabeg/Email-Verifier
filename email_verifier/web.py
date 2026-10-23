from __future__ import annotations

import argparse
import html
import json
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs

from .engine import VerificationConfig, VerificationEngine

MAX_REQUEST_BYTES = 8 * 1024
DEFAULT_SENDER = "verif.mail.evotechly@gmail.com"

STATUS_LABELS = {
    "valid": "Likely deliverable",
    "invalid": "Invalid address",
    "risky": "Potential risk",
    "unknown": "Not enough information",
    "unreachable": "Checks could not finish",
}

STATUS_MEANINGS = {
    "valid": (
        "The checks found positive evidence, but this still does not guarantee inbox delivery."
    ),
    "invalid": (
        "The checks found reliable evidence that the address or its mail domain is invalid."
    ),
    "risky": (
        "The address may work, but it has a risk such as a role mailbox, disposable domain, "
        "or catch-all behavior."
    ),
    "unknown": "The address looks possible, but the mailbox was not confirmed.",
    "unreachable": (
        "A DNS or mail-server check could not complete. This is not proof that the address "
        "is invalid."
    ),
}

REASON_LABELS = {
    "classification.disposable_domain": "The domain is on the disposable-email list.",
    "classification.role_based": "This is a shared role address such as info@ or support@.",
    "dns.disabled": "DNS checking was turned off.",
    "domain.no_mail_routing": "The domain has no usable mail routing records.",
    "domain.nxdomain": "The domain does not exist.",
    "mailbox.not_checked": "The individual mailbox was not checked.",
    "smtp.ambiguous_acceptance": "The mail server accepted the check ambiguously.",
    "smtp.permanent_rejection": "The mail server permanently rejected the address.",
    "smtp.temporary": "The mail server temporarily deferred the check.",
    "smtp.unreachable": "The mail server could not be reached.",
}


PAGE_TEMPLATE = """<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>Email Verifier — Local Test</title>
  <style>
    :root { color-scheme: dark; font-family: system-ui, sans-serif; }
    body { background: #101827; color: #e5e7eb; margin: 0; }
    main { max-width: 820px; margin: 0 auto; padding: 48px 20px; }
    h1 { margin-bottom: 8px; }
    .muted { color: #9ca3af; }
    form, .result-card, details {
      background: #172235; border: 1px solid #334155; border-radius: 12px;
    }
    form { display: grid; gap: 16px; padding: 20px; margin-top: 24px; }
    label { display: grid; gap: 6px; }
    input[type=email], input[type=text] {
      width: 100%; box-sizing: border-box; padding: 10px; border-radius: 8px;
      border: 1px solid #64748b; background: #0f172a; color: #f8fafc;
    }
    .checks { display: flex; flex-wrap: wrap; gap: 16px; }
    .checks label { display: flex; gap: 6px; align-items: center; }
    button {
      width: fit-content; padding: 10px 16px; border: 0; border-radius: 8px;
      background: #38bdf8; color: #082f49; font-weight: 700; cursor: pointer;
    }
    pre { overflow: auto; padding: 16px; line-height: 1.45; white-space: pre-wrap; }
    .notice { padding: 12px 14px; border-left: 4px solid #38bdf8; background: #0f2740; }
    .result-card { margin-top: 24px; padding: 20px; }
    .result-card h2 { margin-top: 0; }
    .status { display: inline-block; padding: 6px 10px; border-radius: 999px; font-weight: 700; }
    .status-valid { border-color: #22c55e; }
    .status-valid .status { background: #14532d; color: #bbf7d0; }
    .status-invalid { border-color: #ef4444; }
    .status-invalid .status { background: #7f1d1d; color: #fecaca; }
    .status-risky { border-color: #f59e0b; }
    .status-risky .status { background: #78350f; color: #fef3c7; }
    .status-unknown, .status-unreachable { border-color: #64748b; }
    .status-unknown .status, .status-unreachable .status { background: #334155; color: #e2e8f0; }
    details { margin-top: 16px; padding: 12px 16px; }
    summary { cursor: pointer; font-weight: 700; }
  </style>
</head>
<body>
  <main>
    <h1>Email Verifier</h1>
    <form method="post" action="/verify">
      <label>Email address
        <input type="email" name="email" value="__EMAIL__" required autocomplete="off" autofocus>
      </label>
      <label>Sender identity for SMTP (no email is sent)
        <input type="email" name="sender" value="__DEFAULT_SENDER__" autocomplete="off">
      </label>
      <div class="checks">
        <label><input type="checkbox" name="dns"__DNS_CHECKED__> DNS</label>
        <label><input type="checkbox" name="smtp"__SMTP_CHECKED__> SMTP RCPT</label>
        <label><input type="checkbox" name="catch_all"__CATCH_ALL_CHECKED__> Catch-all probe</label>
      </div>
      <button type="submit">Verify address</button>
    </form>
    __RESULT__
  </main>
</body>
</html>
"""


def render_page(
    *,
    email: str = "",
    result: dict | None = None,
    dns: bool = True,
    smtp: bool = False,
    catch_all: bool = False,
) -> bytes:
    result_html = ""
    if result is not None:
        status = str(result.get("status", "unknown"))
        status_class = status if status in STATUS_LABELS else "unknown"
        label = STATUS_LABELS.get(status, "Unknown result")
        meaning = STATUS_MEANINGS.get(status, STATUS_MEANINGS["unknown"])
        reasons = result.get("reason_codes") or []
        first_reason = str(reasons[0]) if reasons else ""
        reason = REASON_LABELS.get(first_reason, "The available checks were not conclusive.")
        normalized = result.get("normalized_email") or "Not available"
        stages = result.get("stages_completed") or ["None"]
        serialized = html.escape(json.dumps(result, ensure_ascii=False, indent=2))
        result_html = f"""
        <section class="result-card status-{status_class}" aria-live="polite">
          <h2>Result</h2>
          <p><span class="status">{html.escape(label)}</span></p>
          <p><strong>What this means:</strong> {html.escape(meaning)}</p>
          <p><strong>Main reason:</strong> {html.escape(reason)}</p>
          <ul>
            <li><strong>Email:</strong> {html.escape(str(result.get("original_email", "")))}</li>
            <li><strong>Normalized:</strong> {html.escape(str(normalized))}</li>
            <li><strong>Checks completed:</strong> {html.escape(" → ".join(map(str, stages)))}</li>
          </ul>
          <details>
            <summary>Show technical details</summary>
            <pre>{serialized}</pre>
          </details>
        </section>
        """
    page = PAGE_TEMPLATE
    replacements = {
        "__EMAIL__": html.escape(email, quote=True),
        "__DEFAULT_SENDER__": DEFAULT_SENDER,
        "__DNS_CHECKED__": " checked" if dns else "",
        "__SMTP_CHECKED__": " checked" if smtp else "",
        "__CATCH_ALL_CHECKED__": " checked" if catch_all else "",
        "__RESULT__": result_html,
    }
    for placeholder, value in replacements.items():
        page = page.replace(placeholder, value)
    return page.encode("utf-8")


class LocalRequestHandler(BaseHTTPRequestHandler):
    server_version = "EmailVerifierLocal/1.0"

    def do_GET(self) -> None:  # noqa: N802
        if self.path != "/":
            self._send_text(HTTPStatus.NOT_FOUND, "Not found")
            return
        self._send_html(HTTPStatus.OK, render_page())

    def do_POST(self) -> None:  # noqa: N802
        if self.path != "/verify":
            self._send_text(HTTPStatus.NOT_FOUND, "Not found")
            return
        try:
            length = int(self.headers.get("Content-Length", "-1"))
        except ValueError:
            length = -1
        if length < 0 or length > MAX_REQUEST_BYTES:
            self._send_text(HTTPStatus.REQUEST_ENTITY_TOO_LARGE, "Request is too large")
            return
        fields = parse_qs(self.rfile.read(length).decode("utf-8", errors="replace"))
        email = fields.get("email", [""])[0]
        sender = fields.get("sender", [DEFAULT_SENDER])[0]
        smtp_enabled = "smtp" in fields
        catch_all_enabled = smtp_enabled and "catch_all" in fields
        config = VerificationConfig(
            dns_enabled="dns" in fields,
            smtp_enabled=smtp_enabled,
            catch_all_enabled=catch_all_enabled,
            sender=sender or DEFAULT_SENDER,
        )
        try:
            result = VerificationEngine(config).verify(email).to_dict()
        except (OSError, ValueError) as exc:
            self._send_text(HTTPStatus.BAD_REQUEST, f"Invalid request: {exc}")
            return
        self._send_html(
            HTTPStatus.OK,
            render_page(
                email=email,
                result=result,
                dns="dns" in fields,
                smtp=smtp_enabled,
                catch_all=catch_all_enabled,
            ),
        )

    def log_message(self, format: str, *args: object) -> None:
        # Keep email addresses and result payloads out of the default console log.
        super().log_message("request completed: %s", args[1] if len(args) > 1 else "unknown")

    def _send_html(self, status: HTTPStatus, body: bytes) -> None:
        self.send_response(status)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Content-Security-Policy", "default-src 'none'; style-src 'unsafe-inline'")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(body)

    def _send_text(self, status: HTTPStatus, message: str) -> None:
        body = (message + "\n").encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "text/plain; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("X-Content-Type-Options", "nosniff")
        self.end_headers()
        self.wfile.write(body)


def create_server(host: str = "127.0.0.1", port: int = 8000) -> ThreadingHTTPServer:
    return ThreadingHTTPServer((host, port), LocalRequestHandler)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Run the local Email-Verifier test page")
    parser.add_argument("--host", default="127.0.0.1", help="bind address (default: 127.0.0.1)")
    parser.add_argument("--port", type=int, default=8765)
    args = parser.parse_args(argv)
    if args.host not in {"127.0.0.1", "::1", "localhost"}:
        parser.error("the local test server only permits loopback hosts")
    server = create_server(args.host, args.port)
    print(f"Email Verifier local UI: http://{args.host}:{server.server_port}")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\nStopping local UI")
    finally:
        server.server_close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
