from __future__ import annotations

import csv
import json
import os
from pathlib import Path
from typing import Iterable

from .bulk import BulkRecord


def safe_csv_cell(value: object) -> str:
    text = "" if value is None else str(value)
    leading_control = bool(text) and ord(text[0]) < 32 and text[0] not in " \t\r\n"
    if leading_control or text.lstrip(" \t\r\n").startswith(("=", "+", "-", "@")):
        return "'" + text
    return text


def write_csv(
    records: Iterable[BulkRecord], path: str | Path, *, input_path: str | Path | None = None
) -> int:
    count = 0
    with _safe_output(path, input_path=input_path) as handle:
        writer = csv.DictWriter(
            handle,
            fieldnames=[
                "input_id",
                "original",
                "status",
                "normalized_email",
                "reason_codes",
                "error",
            ],
        )
        writer.writeheader()
        for record in records:
            result = record.result or {}
            writer.writerow(
                {
                    "input_id": safe_csv_cell(record.input_id),
                    "original": safe_csv_cell(record.original),
                    "status": safe_csv_cell(result.get("status")),
                    "normalized_email": safe_csv_cell(result.get("normalized_email")),
                    "reason_codes": safe_csv_cell(";".join(result.get("reason_codes", []))),
                    "error": safe_csv_cell(record.error),
                }
            )
            count += 1
    return count


def write_jsonl(
    records: Iterable[BulkRecord], path: str | Path, *, input_path: str | Path | None = None
) -> int:
    count = 0
    with _safe_output(path, input_path=input_path) as handle:
        for record in records:
            payload = {
                "input_id": record.input_id,
                "original": record.original,
                "result": record.result,
                "error": record.error,
            }
            handle.write(json.dumps(payload, ensure_ascii=False, separators=(",", ":")) + "\n")
            count += 1
    return count


def _safe_output(path: str | Path, *, input_path: str | Path | None = None):
    output = Path(path)
    if input_path is not None and output.resolve() == Path(input_path).resolve():
        raise ValueError("output path must differ from input path")
    flags = os.O_WRONLY | os.O_CREAT | os.O_TRUNC
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    try:
        descriptor = os.open(output, flags, 0o600)
    except OSError as exc:
        raise OSError(f"cannot safely open output file: {output}") from exc
    os.fchmod(descriptor, 0o600)
    return os.fdopen(descriptor, "w", encoding="utf-8", newline="")
