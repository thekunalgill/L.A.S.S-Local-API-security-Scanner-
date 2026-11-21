import unittest

from lass.scanner import analyze_response
from lass.scoring import score_findings


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
