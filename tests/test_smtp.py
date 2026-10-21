import unittest

from email_verifier.smtp import _response_outcome


class SmtpTests(unittest.TestCase):
    def test_response_categories(self):
        self.assertEqual(_response_outcome(250), "accepted")
        self.assertEqual(_response_outcome(252), "ambiguous")
        self.assertEqual(_response_outcome(451), "temporary")
        self.assertEqual(_response_outcome(550), "rejected")
