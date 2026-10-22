# Email-Verifier

Email-Verifier is a conservative Python email verification engine and command-line tool. It validates syntax, normalizes internationalized domains, checks DNS mail routing, optionally performs a controlled SMTP `RCPT TO` check, and classifies disposable and role-based addresses.

It is a deliverability signal, not a guarantee that a message will reach an inbox. DNS proves that a domain has mail routing; SMTP acceptance can be deliberately ambiguous, catch-all servers can accept nonexistent recipients, and providers can defer or conceal mailbox existence.

## What it returns

Each result includes the original input, normalized address, explicit status, completed stages, DNS/MX details, SMTP response category when enabled, catch-all state, disposable and role-based indicators, reason codes, evidence level, timestamp, and duration.

Statuses are:

- `valid`: SMTP accepted the recipient and no higher-risk classification applied. This does not guarantee delivery.
- `invalid`: syntax, domain existence, mail routing, or a permanent SMTP rejection is reliable negative evidence.
- `risky`: disposable, role-based, catch-all, or ambiguous-provider behavior was detected.
- `unknown`: the address may work, but mailbox evidence was not collected or was insufficient.
- `unreachable`: DNS or network checks could not complete. A timeout is never treated as proof of invalidity.

## Install

Python 3.11+ is required.

```bash
python -m venv .venv
. .venv/bin/activate
python -m pip install -e '.[dev]'
```

## Local test environment

The repository includes a small deterministic smoke environment. It uses only
reserved `example.com` addresses and disables DNS, SMTP, and catch-all probes,
so it is safe to run offline and does not contact mail providers.

```bash
make setup
make check
make demo
```

If you already have the dependencies installed, run `./scripts/demo.sh`
directly. To perform an intentional live DNS check, use the single-address
command without `--no-dns`; SMTP and catch-all checks remain explicit opt-ins.

## Local browser interface

Start the localhost-only browser interface with:

```bash
make serve
```

Then open <http://127.0.0.1:8000>. The page uses the same engine as the CLI,
defaults to DNS-only verification, and keeps SMTP and catch-all probing behind
explicit opt-in checkboxes. Stop it with `Ctrl+C`.

## Single address

DNS checks are enabled by default. SMTP probing is opt-in because it can be rate-limited or refused by providers.

```bash
email-verifier verify person@example.com --pretty
email-verifier verify person@example.com --smtp --sender verify@example.com
```

`--smtp` performs `EHLO`, optional opportunistic `STARTTLS`, `MAIL FROM`, and `RCPT TO` without sending a message. `--catch-all` enables at most one randomized recipient probe after a positive SMTP result. Do not enable either option against domains you do not have permission to assess.

## Bulk files

TXT files are streamed one address per line. CSV files are streamed and use a column named `email`, `email_address`, or `address` by default.

```bash
email-verifier bulk addresses.txt --output results.csv --concurrency 4 --rate-limit 2
email-verifier bulk addresses.csv --output results.jsonl --output-format jsonl --email-column work_email
email-verifier bulk addresses.txt --stdout --output-format jsonl
```

Bulk processing is bounded by batches, uses a disk-backed SQLite result cache to deduplicate repeated normalized addresses, preserves input row IDs and original values, and continues after malformed rows or individual verification errors. CSV exports escape formula-like cells to reduce spreadsheet formula injection risk. The default upload/read limit is 50 MiB and can be changed with `--max-file-bytes`.

Bulk mode requires an explicit `--output` path or `--stdout` because raw addresses and results are sensitive. Output files are created with mode `0600`, symlink targets are rejected, and the output path cannot equal the input path.

## Configuration and datasets

CLI flags take precedence over the example environment settings in `.env.example`. The built-in disposable domain list is intentionally conservative and is not an exhaustive source of truth. Provide a newline-delimited maintained dataset with `--classifier-file`. Role-based detection is advisory and does not make an address invalid.

## Architecture

- `syntax.py`: supported syntax and IDN normalization without changing the local part.
- `dns.py`: MX-first resolver, A/AAAA implicit routing fallback, explicit DNS outcomes, and bounded TTL cache.
- `smtp.py`: safe connection lifecycle, TLS mode, response categorization, and no-message verification.
- `engine.py`: stage orchestration and documented status precedence.
- `bulk.py`: streaming records, bounded concurrency, rate limiting, cancellation, and deduplication.
- `export.py`: CSV/JSONL output and formula-injection defense.

Network and SMTP behavior are injected behind interfaces, so the test suite uses deterministic fakes and does not contact arbitrary mailboxes or external providers.

When SMTP is enabled, at most three MX hosts are attempted per address by default. MX targets are resolved before connection and non-public destinations are rejected to reduce SSRF-style risk. These controls do not replace operator authorization or provider terms.

## Privacy and responsible operation

Email addresses are personal data in many jurisdictions. Avoid logging raw lists, protect result files, use a sender identity you control, throttle requests, and follow provider terms and applicable law. This project does not send messages, bypass anti-abuse controls, use open relays, or validate credentials.

## Development

```bash
python -m unittest discover -v
python -m pytest
ruff check .
```

The CI workflow runs tests and linting on pushes and pull requests. Live DNS and SMTP checks are intentionally not part of CI.

## Limitations

The bundled classifier list needs operational maintenance. Some providers accept every recipient, suppress recipient errors, require authentication, greylist, or block verification traffic. SMTP `250` means the server accepted the transaction at that moment; it does not prove that a mailbox exists or that a later message will be delivered.
