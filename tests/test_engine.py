import unittest

from email_verifier.classifiers import ClassifierData
from email_verifier.dns import StaticResolver
from email_verifier.engine import VerificationConfig, VerificationEngine
from email_verifier.models import DnsResult, SmtpResult


class FakeSmtp:
    def __init__(self, outcomes):
        self.outcomes = list(outcomes)
        self.calls = []

    def verify(self, recipient, hosts):
        self.calls.append((recipient, hosts))
        outcome = self.outcomes.pop(0)
        return SmtpResult(
            outcome=outcome, mx_host=hosts[0] if hosts else None, attempted_hosts=hosts
        )


def engine(*, smtp=False, catch_all=False, smtp_outcomes=None):
    resolver = StaticResolver(
        {
            "example.com": DnsResult("example.com", "mx", mx_records=["mx.example.com"]),
            "mailinator.com": DnsResult("mailinator.com", "mx", mx_records=["mx.mailinator.com"]),
            "no-mail.example": DnsResult("no-mail.example", "no_mail_routing", error_code="no_mx"),
            "timeout.example": DnsResult("timeout.example", "timeout", error_code="timeout"),
            "xn--bcher-kva.example": DnsResult(
                "xn--bcher-kva.example", "mx", mx_records=["mx.example"]
            ),
        }
    )
    fake = FakeSmtp(smtp_outcomes or ["accepted"])
    data = ClassifierData(disposable_domains=frozenset({"mailinator.com"}))
    return VerificationEngine(
        VerificationConfig(
            resolver=resolver,
            smtp_verifier=fake,
            smtp_enabled=smtp,
            catch_all_enabled=catch_all,
            classifier_data=data,
        )
    ), fake


class EngineTests(unittest.TestCase):
    def test_syntax_failure_does_not_query_dns(self):
        verifier, _ = engine()
        result = verifier.verify("not-an-address")
        self.assertEqual(result.status, "invalid")
        self.assertIn("syntax.missing_at", result.reason_codes)

    def test_nxdomain_and_dns_timeout_are_distinct(self):
        verifier, _ = engine()
        self.assertEqual(verifier.verify("a@no-mail.example").status, "invalid")
        self.assertEqual(verifier.verify("a@timeout.example").status, "unreachable")

    def test_dns_only_is_unknown_not_valid(self):
        verifier, fake = engine()
        result = verifier.verify("person@example.com")
        self.assertEqual(result.status, "unknown")
        self.assertFalse(fake.calls)

    def test_smtp_acceptance_is_valid_but_role_and_disposable_are_risky(self):
        verifier, _ = engine(smtp=True, smtp_outcomes=["accepted", "accepted"])
        self.assertEqual(verifier.verify("person@example.com").status, "valid")
        self.assertEqual(verifier.verify("info@mailinator.com").status, "risky")

    def test_permanent_smtp_rejection_is_invalid(self):
        verifier, _ = engine(smtp=True, smtp_outcomes=["rejected"])
        result = verifier.verify("person@example.com")
        self.assertEqual(result.status, "invalid")
        self.assertIn("smtp.permanent_rejection", result.reason_codes)

    def test_temporary_smtp_response_is_unknown(self):
        verifier, _ = engine(smtp=True, smtp_outcomes=["temporary"])
        result = verifier.verify("person@example.com")
        self.assertEqual(result.status, "unknown")
        self.assertIn("smtp.temporary", result.reason_codes)

    def test_catch_all_is_risky_and_uses_one_probe(self):
        verifier, fake = engine(smtp=True, catch_all=True, smtp_outcomes=["accepted", "accepted"])
        result = verifier.verify("person@example.com")
        self.assertEqual(result.status, "risky")
        self.assertEqual(result.catch_all.status, "detected")
        self.assertEqual(len(fake.calls), 2)
        self.assertNotEqual(fake.calls[0][0], fake.calls[1][0])
