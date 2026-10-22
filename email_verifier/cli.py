from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path

from .bulk import BulkVerifier, iter_input_records
from .classifiers import ClassifierData
from .engine import VerificationConfig, VerificationEngine
from .export import write_csv, write_jsonl


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="email-verifier",
        description="Conservative email syntax, DNS, and opt-in SMTP verification",
    )
    subparsers = parser.add_subparsers(dest="command", required=True)

    verify = subparsers.add_parser("verify", help="verify one address")
    verify.add_argument("email")
    _add_engine_options(verify)
    verify.add_argument("--pretty", action="store_true", help="pretty-print JSON")

    bulk = subparsers.add_parser("bulk", help="stream and verify a CSV or TXT file")
    bulk.add_argument("input", type=Path)
    output_group = bulk.add_mutually_exclusive_group()
    output_group.add_argument("--output", type=Path)
    output_group.add_argument(
        "--stdout", action="store_true", help="explicitly write raw rows to stdout"
    )
    bulk.add_argument("--output-format", choices=["csv", "jsonl"], default="csv")
    bulk.add_argument("--input-format", choices=["auto", "csv", "txt"], default="auto")
    bulk.add_argument("--email-column")
    bulk.add_argument("--max-file-bytes", type=int, default=50 * 1024 * 1024)
    bulk.add_argument(
        "--concurrency", type=int, default=int(os.getenv("EMAIL_VERIFIER_CONCURRENCY", "4"))
    )
    bulk.add_argument(
        "--rate-limit",
        type=float,
        default=float(os.getenv("EMAIL_VERIFIER_RATE_LIMIT", "1")),
        help="verification attempts per second; 0 disables throttling",
    )
    _add_engine_options(bulk)
    return parser


def _add_engine_options(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--no-dns", action="store_true", help="skip DNS checks")
    parser.add_argument("--smtp", action="store_true", help="enable opt-in SMTP RCPT verification")
    parser.add_argument(
        "--catch-all", action="store_true", help="enable one controlled catch-all probe per address"
    )
    parser.add_argument(
        "--sender",
        default=os.getenv("EMAIL_VERIFIER_SENDER", "verif.mail.evotechly@gmail.com"),
    )
    parser.add_argument(
        "--dns-timeout", type=float, default=float(os.getenv("EMAIL_VERIFIER_DNS_TIMEOUT", "3"))
    )
    parser.add_argument(
        "--smtp-timeout", type=float, default=float(os.getenv("EMAIL_VERIFIER_SMTP_TIMEOUT", "8"))
    )
    parser.add_argument(
        "--classifier-file", type=Path, help="newline-delimited disposable domain dataset"
    )


def _engine_from_args(args: argparse.Namespace) -> VerificationEngine:
    data = ClassifierData.load(args.classifier_file) if args.classifier_file else None
    config = VerificationConfig(
        dns_enabled=not args.no_dns,
        smtp_enabled=args.smtp,
        catch_all_enabled=args.catch_all,
        sender=args.sender,
        dns_timeout=max(0.1, args.dns_timeout),
        smtp_timeout=max(0.1, args.smtp_timeout),
        classifier_data=data,
    )
    return VerificationEngine(config)


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    try:
        if args.command == "verify":
            result = _engine_from_args(args).verify(args.email)
            print(
                json.dumps(result.to_dict(), ensure_ascii=False, indent=2 if args.pretty else None)
            )
            return 0
        if args.concurrency > 64:
            raise ValueError("concurrency cannot exceed 64")
        if not args.output and not args.stdout:
            raise ValueError("bulk requires --output or explicit --stdout")
        engine = _engine_from_args(args)
        verifier = BulkVerifier(engine, concurrency=args.concurrency, rate_limit=args.rate_limit)
        records = verifier.verify_records(
            iter_input_records(
                args.input,
                input_format=args.input_format,
                email_column=args.email_column,
                max_bytes=args.max_file_bytes,
            )
        )
        if args.output:
            count = (
                write_csv(records, args.output, input_path=args.input)
                if args.output_format == "csv"
                else write_jsonl(records, args.output, input_path=args.input)
            )
            print(
                json.dumps(
                    {"processed": count, "output": str(args.output), "format": args.output_format}
                )
            )
        else:
            for record in records:
                print(
                    json.dumps(
                        {
                            "input_id": record.input_id,
                            "original": record.original,
                            "result": record.result,
                            "error": record.error,
                        },
                        ensure_ascii=False,
                    )
                )
        return 0
    except (OSError, ValueError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
