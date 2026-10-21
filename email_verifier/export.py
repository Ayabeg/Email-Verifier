from __future__ import annotations

import csv
import json
from pathlib import Path
from typing import Iterable

from .bulk import BulkRecord


def safe_csv_cell(value: object) -> str:
    text = "" if value is None else str(value)
    if text.startswith(("=", "+", "-", "@")):
        return "'" + text
    return text


def write_csv(records: Iterable[BulkRecord], path: str | Path) -> int:
    count = 0
    with Path(path).open("w", encoding="utf-8", newline="") as handle:
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


def write_jsonl(records: Iterable[BulkRecord], path: str | Path) -> int:
    count = 0
    with Path(path).open("w", encoding="utf-8") as handle:
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
