from __future__ import annotations

import argparse
import html
import json
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs

from .engine import VerificationConfig, VerificationEngine

MAX_REQUEST_BYTES = 8 * 1024


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
    form, pre { background: #172235; border: 1px solid #334155; border-radius: 12px; }
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
  </style>
</head>
<body>
  <main>
    <h1>Email Verifier</h1>
    <p class="muted">Local test interface. Results are signals, not a guarantee of
      inbox delivery.</p>
    <p class="notice">This server listens on 127.0.0.1 only. SMTP and catch-all
      checks are opt-in and should only be used where you have permission.</p>
    <form method="post" action="/verify">
      <label>Email address
        <input type="email" name="email" value="__EMAIL__" required autocomplete="off" autofocus>
      </label>
      <label>Sender identity for SMTP (only used when SMTP is enabled)
        <input type="email" name="sender" value="verify@example.com" autocomplete="off">
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
        serialized = html.escape(json.dumps(result, ensure_ascii=False, indent=2))
        result_html = f"<h2>Result</h2><pre>{serialized}</pre>"
    page = PAGE_TEMPLATE
    replacements = {
        "__EMAIL__": html.escape(email, quote=True),
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
        sender = fields.get("sender", ["verify@example.com"])[0]
        smtp_enabled = "smtp" in fields
        catch_all_enabled = smtp_enabled and "catch_all" in fields
        config = VerificationConfig(
            dns_enabled="dns" in fields,
            smtp_enabled=smtp_enabled,
            catch_all_enabled=catch_all_enabled,
            sender=sender or "verify@example.com",
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
    parser.add_argument("--port", type=int, default=8000)
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
