import unittest

from email_verifier.syntax import parse_email


class SyntaxTests(unittest.TestCase):
    def test_normalizes_domain_without_lowercasing_local_part(self):
        result = parse_email(" Alice+tag@BÜCHER.example ")
        self.assertTrue(result.valid)
        self.assertEqual(result.normalized_email, "Alice+tag@xn--bcher-kva.example")

    def test_supports_quoted_local_part(self):
        self.assertTrue(parse_email('"a\\"b"@example.com').valid)

    def test_rejects_display_name_and_malformed_addresses(self):
        for value in [
            "Alice <alice@example.com>",
            "a..b@example.com",
            "@example.com",
            "a@example..com",
            "a b@example.com",
        ]:
            self.assertFalse(parse_email(value).valid, value)

    def test_rejects_controls_and_domain_hyphen(self):
        self.assertEqual(parse_email("a\n@example.com").reason_code, "syntax.control_character")
        self.assertFalse(parse_email("a@-example.com").valid)
