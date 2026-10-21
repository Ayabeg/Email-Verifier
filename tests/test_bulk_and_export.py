import csv
import tempfile
import unittest
from pathlib import Path

from email_verifier.bulk import BulkRecord, BulkVerifier, iter_input_records
from email_verifier.dns import StaticResolver
from email_verifier.engine import VerificationConfig, VerificationEngine
from email_verifier.export import safe_csv_cell, write_csv
from email_verifier.models import DnsResult


class BulkTests(unittest.TestCase):
    def setUp(self):
        resolver = StaticResolver(
            {"example.com": DnsResult("example.com", "mx", mx_records=["mx.example.com"])}
        )
        self.engine = VerificationEngine(VerificationConfig(resolver=resolver))

    def test_streams_csv_and_deduplicates_work(self):
        with tempfile.TemporaryDirectory() as directory:
            source = Path(directory) / "input.csv"
            source.write_text(
                "name,email\nfirst,person@example.com\nsecond,person@example.com\nthird,\n",
                encoding="utf-8",
            )
            rows = list(iter_input_records(source))
            results = list(
                BulkVerifier(self.engine, concurrency=2, rate_limit=0).verify_records(iter(rows))
            )
            self.assertEqual([row.input_id for row in results], [2, 3, 4])
            self.assertEqual(results[0].result["status"], "unknown")
            self.assertEqual(results[1].result["status"], "unknown")
            self.assertEqual(results[2].error, "missing_email")

    def test_csv_export_escapes_formula_cells(self):
        self.assertEqual(safe_csv_cell("=SUM(A1:A2)"), "'=SUM(A1:A2)")
        self.assertEqual(safe_csv_cell("\t=SUM(A1:A2)"), "'\t=SUM(A1:A2)")
        self.assertEqual(safe_csv_cell("\x1b=SUM(A1:A2)"), "'\x1b=SUM(A1:A2)")
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory) / "out.csv"
            write_csv(
                [
                    BulkRecord(
                        1,
                        "=1+1",
                        {"status": "unknown", "normalized_email": None, "reason_codes": []},
                    )
                ],
                output,
            )
            with output.open(newline="", encoding="utf-8") as handle:
                row = next(csv.DictReader(handle))
            self.assertEqual(row["original"], "'=1+1")

    def test_output_cannot_clobber_input(self):
        with tempfile.TemporaryDirectory() as directory:
            source = Path(directory) / "input.txt"
            source.write_text("person@example.com\n", encoding="utf-8")
            with self.assertRaises(ValueError):
                write_csv([], source, input_path=source)


if __name__ == "__main__":
    unittest.main()
