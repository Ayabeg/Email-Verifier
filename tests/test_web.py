import threading
import unittest
from http.client import HTTPConnection

from email_verifier.web import create_server, render_page


class LocalWebTests(unittest.TestCase):
    def setUp(self):
        self.server = create_server("127.0.0.1", 0)
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()

    def tearDown(self):
        self.server.shutdown()
        self.server.server_close()
        self.thread.join(timeout=2)

    def request(self, method: str, path: str, body: str | None = None):
        connection = HTTPConnection("127.0.0.1", self.server.server_port, timeout=3)
        headers = {"Content-Type": "application/x-www-form-urlencoded"} if body else {}
        connection.request(method, path, body=body, headers=headers)
        response = connection.getresponse()
        payload = response.read()
        connection.close()
        return response, payload

    def test_home_page_is_available(self):
        response, payload = self.request("GET", "/")
        self.assertEqual(response.status, 200)
        self.assertIn(b"Email Verifier", payload)
        self.assertIn(b"verif.mail.evotechly@gmail.com", payload)
        self.assertEqual(
            response.getheader("Content-Security-Policy"),
            "default-src 'none'; style-src 'unsafe-inline'",
        )

    def test_verify_without_dns_returns_structured_result(self):
        response, payload = self.request(
            "POST", "/verify", "email=person%40example.com&sender=verify%40example.com"
        )
        self.assertEqual(response.status, 200)
        page = payload.decode("utf-8")
        self.assertIn("Not enough information", page)
        self.assertIn("DNS checking was turned off.", page)
        self.assertIn("Show technical details", page)

    def test_malformed_address_is_rendered_as_invalid(self):
        response, payload = self.request("POST", "/verify", "email=not-an-email")
        self.assertEqual(response.status, 200)
        self.assertIn("Invalid address", payload.decode("utf-8"))

    def test_success_result_without_reason_codes_is_rendered(self):
        page = render_page(
            email="person@example.com",
            result={
                "status": "valid",
                "original_email": "person@example.com",
                "normalized_email": "person@example.com",
                "reason_codes": [],
                "stages_completed": ["syntax", "dns", "smtp"],
            },
        ).decode("utf-8")
        self.assertIn("Likely deliverable", page)
        self.assertIn("The available checks were not conclusive.", page)

    def test_unknown_route_is_not_found(self):
        response, _ = self.request("GET", "/missing")
        self.assertEqual(response.status, 404)


if __name__ == "__main__":
    unittest.main()
