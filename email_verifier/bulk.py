from __future__ import annotations

import csv
import json
import os
import sqlite3
import tempfile
import threading
import time
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass
from pathlib import Path
from typing import Iterator

from .engine import VerificationEngine
from .syntax import parse_email


@dataclass(slots=True)
class InputRecord:
    input_id: int
    original: str
    email: str | None
    error: str | None = None


@dataclass(slots=True)
class BulkRecord:
    input_id: int
    original: str
    result: dict | None = None
    error: str | None = None


class RateLimiter:
    def __init__(self, per_second: float) -> None:
        self.interval = 1.0 / per_second if per_second > 0 else 0.0
        self._next_allowed = 0.0
        self._lock = threading.Lock()

    def wait(self, cancel_event: threading.Event | None = None) -> None:
        if self.interval == 0:
            return
        with self._lock:
            now = time.monotonic()
            target = max(now, self._next_allowed)
            self._next_allowed = target + self.interval
        delay = target - now
        if delay > 0 and cancel_event is not None:
            if cancel_event.wait(delay):
                return
        elif delay > 0:
            time.sleep(delay)


def iter_input_records(
    path: str | Path,
    *,
    input_format: str = "auto",
    email_column: str | None = None,
    max_bytes: int = 50 * 1024 * 1024,
) -> Iterator[InputRecord]:
    source = Path(path)
    if not source.is_file():
        raise FileNotFoundError(str(source))
    selected = input_format
    if selected == "auto":
        selected = "csv" if source.suffix.lower() == ".csv" else "txt"
    if selected not in {"csv", "txt"}:
        raise ValueError("input format must be csv, txt, or auto")
    if selected == "txt":
        with source.open("r", encoding="utf-8-sig", newline="") as handle:
            if os.fstat(handle.fileno()).st_size > max_bytes:
                raise ValueError(f"input file exceeds the {max_bytes} byte limit")
            for input_id, line in enumerate(handle, start=1):
                original = line.rstrip("\r\n")
                yield InputRecord(
                    input_id,
                    original,
                    original if original else None,
                    None if original else "empty_row",
                )
        return
    with source.open("r", encoding="utf-8-sig", newline="") as handle:
        if os.fstat(handle.fileno()).st_size > max_bytes:
            raise ValueError(f"input file exceeds the {max_bytes} byte limit")
        reader = csv.DictReader(handle)
        if not reader.fieldnames:
            raise ValueError("CSV input must include a header row")
        column = email_column or next(
            (
                name
                for name in reader.fieldnames
                if name and name.strip().lower() in {"email", "email_address", "address"}
            ),
            reader.fieldnames[0],
        )
        if column not in reader.fieldnames:
            raise ValueError(f"CSV email column not found: {column}")
        for input_id, row in enumerate(reader, start=2):
            original = (row.get(column) or "").strip()
            error = None if original else "missing_email"
            yield InputRecord(input_id, original, original or None, error)


class BulkVerifier:
    def __init__(
        self,
        engine: VerificationEngine,
        *,
        concurrency: int = 4,
        rate_limit: float = 1.0,
        batch_size: int | None = None,
        cancel_event: threading.Event | None = None,
    ) -> None:
        if concurrency < 1 or concurrency > 64:
            raise ValueError("concurrency must be between 1 and 64")
        self.engine = engine
        self.concurrency = concurrency
        self.batch_size = max(concurrency, batch_size or concurrency * 4)
        self.limiter = RateLimiter(rate_limit)
        self.cancel_event = cancel_event or threading.Event()

    def verify_records(self, records: Iterator[InputRecord]) -> Iterator[BulkRecord]:
        with tempfile.NamedTemporaryFile(prefix="email-verifier-", suffix=".sqlite3") as cache_file:
            connection = sqlite3.connect(cache_file.name)
            connection.execute(
                "CREATE TABLE results (dedupe_key TEXT PRIMARY KEY, payload TEXT NOT NULL)"
            )
            try:
                batch: list[InputRecord] = []
                for record in records:
                    batch.append(record)
                    if len(batch) >= self.batch_size:
                        yield from self._process_batch(batch, connection)
                        batch = []
                if batch:
                    yield from self._process_batch(batch, connection)
            finally:
                connection.close()

    def _process_batch(
        self, batch: list[InputRecord], connection: sqlite3.Connection
    ) -> Iterator[BulkRecord]:
        if self.cancel_event.is_set():
            for record in batch:
                yield BulkRecord(record.input_id, record.original, error="cancelled")
            return
        pending: dict[str, InputRecord] = {}
        output: dict[int, BulkRecord] = {}
        for record in batch:
            if record.error or record.email is None:
                output[record.input_id] = BulkRecord(
                    record.input_id, record.original, error=record.error or "invalid_row"
                )
                continue
            key = _dedupe_key(record.email)
            cached = connection.execute(
                "SELECT payload FROM results WHERE dedupe_key = ?", (key,)
            ).fetchone()
            if cached:
                output[record.input_id] = BulkRecord(
                    record.input_id, record.original, result=json.loads(cached[0])
                )
            else:
                pending.setdefault(key, record)
        if pending:
            with ThreadPoolExecutor(
                max_workers=self.concurrency, thread_name_prefix="email-verify"
            ) as pool:
                futures = {
                    key: pool.submit(self._verify_one, record.email or "")
                    for key, record in pending.items()
                }
                for key, future in futures.items():
                    try:
                        result = future.result().to_dict()
                        connection.execute(
                            "INSERT OR REPLACE INTO results VALUES (?, ?)",
                            (key, json.dumps(result, separators=(",", ":"))),
                        )
                        for record in batch:
                            if record.email is not None and _dedupe_key(record.email) == key:
                                output[record.input_id] = BulkRecord(
                                    record.input_id, record.original, result=result
                                )
                    except Exception as exc:  # one bad address must not abort a batch
                        for record in batch:
                            if record.email is not None and _dedupe_key(record.email) == key:
                                error = (
                                    "cancelled"
                                    if self.cancel_event.is_set()
                                    else f"verification_error:{type(exc).__name__}"
                                )
                                output[record.input_id] = BulkRecord(
                                    record.input_id, record.original, error=error
                                )
            connection.commit()
        for record in batch:
            item = output.get(record.input_id)
            if item is not None:
                yield item

    def _verify_one(self, email: str):
        if self.cancel_event.is_set():
            raise RuntimeError("cancelled")
        self.limiter.wait(self.cancel_event)
        if self.cancel_event.is_set():
            raise RuntimeError("cancelled")
        return self.engine.verify(email)


def _dedupe_key(email: str) -> str:
    parsed = parse_email(email)
    if parsed.valid and parsed.normalized_email:
        return parsed.normalized_email
    return email.strip().casefold()
