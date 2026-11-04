import unittest
from unittest.mock import patch

from lass.scanner import analyze_response, score_findings
from lass.security import (
    TargetValidationError,
    validate_public_target_url,
    validate_target_url,
)


class TargetValidationTests(unittest.TestCase):
    def test_normalizes_localhost_and_allows_loopback(self):
        self.assertEqual(
            validate_target_url("http://localhost:8000/health"),
            "http://127.0.0.1:8000/health",
        )
        self.assertEqual(
            validate_target_url("http://[::1]:9000/"),
            "http://[::1]:9000/",
        )

    def test_allows_private_ipv4_and_ipv6_targets(self):
        self.assertEqual(
            validate_target_url("http://192.168.1.25:8080"),
            "http://192.168.1.25:8080/",
        )
        self.assertEqual(
            validate_target_url("http://[fd00::25]:8080"),
            "http://[fd00::25]:8080/",
        )

    def test_rejects_public_hosts_and_malformed_urls(self):
        for target in (
            "https://example.com/",
            "http://8.8.8.8/",
            "ftp://localhost/file",
            "http://user:pass@localhost/",
            "http://localhost/#fragment",
        ):
            with self.subTest(target=target), self.assertRaises(TargetValidationError):
                validate_target_url(target)

    @patch("lass.security.socket.getaddrinfo")
    def test_hosted_mode_allows_publicly_resolving_hostnames(self, resolve):
        resolve.return_value = [(None, None, None, None, ("93.184.216.34", 443))]
        self.assertEqual(
            validate_public_target_url("https://api.example.com/health"),
            ("https://api.example.com/health", "93.184.216.34"),
        )

        resolve.return_value = [(None, None, None, None, ("10.0.0.8", 443))]
        with self.assertRaises(TargetValidationError):
            validate_public_target_url("https://api.example.com/health")

    def test_hosted_mode_rejects_non_global_ip_targets(self):
        with self.assertRaises(TargetValidationError):
            validate_public_target_url("http://127.0.0.1/")

    def test_hosted_mode_allows_public_ip_targets(self):
        self.assertEqual(
            validate_public_target_url("https://8.8.8.8/"),
            ("https://8.8.8.8/", "8.8.8.8"),
        )


class ScannerTests(unittest.TestCase):
    def test_finds_missing_headers_cors_and_server_disclosure(self):
        findings = analyze_response(
            200,
            {
                "Access-Control-Allow-Origin": "*",
                "Server": "example/1.2",
                "X-Content-Type-Options": "nosniff",
            },
            is_https=False,
        )
        codes = {finding["code"] for finding in findings}
        self.assertIn("cors_wildcard", codes)
        self.assertIn("technology_disclosure_server", codes)
        self.assertIn("content_security_policy", codes)
        self.assertNotIn("strict_transport_security", codes)
        self.assertLess(score_findings(findings), 100)

    def test_reports_server_errors_and_deducts_by_severity(self):
        findings = analyze_response(503, {}, is_https=True)
        self.assertIn("http_server_error", {finding["code"] for finding in findings})
        self.assertIn("strict_transport_security", {finding["code"] for finding in findings})
        self.assertEqual(score_findings(findings), 45)


if __name__ == "__main__":
    unittest.main()
