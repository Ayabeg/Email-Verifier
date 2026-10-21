import unittest
from unittest.mock import patch

from email_verifier.models import SmtpResult
from email_verifier.smtp import SmtpConfig, SmtpVerifier, _response_outcome, _select_public_address


class SmtpTests(unittest.TestCase):
    def test_response_categories(self):
        self.assertEqual(_response_outcome(250), "accepted")
        self.assertEqual(_response_outcome(252), "ambiguous")
        self.assertEqual(_response_outcome(451), "temporary")
        self.assertEqual(_response_outcome(550), "rejected")

    @patch("email_verifier.smtp.socket.getaddrinfo")
    def test_private_targets_are_rejected_before_connect(self, getaddrinfo):
        getaddrinfo.return_value = [(2, 1, 6, "", ("127.0.0.1", 25))]
        self.assertIsNone(_select_public_address("internal.example", 25))

    def test_smtp_attempts_are_capped(self):
        verifier = SmtpVerifier(SmtpConfig(sender="verify@example.com", max_hosts=2))
        with patch.object(
            verifier,
            "_verify_host",
            return_value=SmtpResult(outcome="unreachable"),
        ) as verify_host:
            verifier.verify("person@example.com", ["one", "two", "three"])
        self.assertEqual(verify_host.call_count, 2)
