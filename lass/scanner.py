from __future__ import annotations

from typing import Any


def analyze_response(
    status_code: int, headers: Any, is_https: bool
) -> list[dict[str, str]]:
    normalized = {name.lower(): value.strip() for name, value in headers.items()}
    findings: list[dict[str, str]] = []

    if status_code >= 500:
        findings.append(
            {
                "code": "http_server_error",
                "severity": "high",
                "title": f"API returned HTTP {status_code}",
                "detail": "The endpoint responded with a server error.",
                "recommendation": "Inspect the API logs and return an appropriate response without exposing internal details.",
            }
        )

    for code, header, severity, title, recommendation in [
        (
            "x_content_type_options",
            "x-content-type-options",
            "medium",
            "Missing X-Content-Type-Options",
            "Send X-Content-Type-Options: nosniff to prevent browsers from guessing response content types.",
        ),
        (
            "content_security_policy",
            "content-security-policy",
            "low",
            "Missing Content-Security-Policy",
            "If this API serves browser-rendered content, define a restrictive Content-Security-Policy.",
        ),
        (
            "x_frame_options",
            "x-frame-options",
            "low",
            "Missing X-Frame-Options",
            "For browser-rendered pages, send X-Frame-Options: DENY or use CSP frame-ancestors.",
        ),
        (
            "referrer_policy",
            "referrer-policy",
            "low",
            "Missing Referrer-Policy",
            "Set a restrictive Referrer-Policy such as strict-origin-when-cross-origin.",
        ),
        *(
            [
                (
                    "strict_transport_security",
                    "strict-transport-security",
                    "medium",
                    "Missing Strict-Transport-Security",
                    "Enable HSTS only after HTTPS is correctly configured for this host.",
                )
            ]
            if is_https
            else []
        ),
    ]:
        if header not in normalized:
            findings.append(
                {
                    "code": code,
                    "severity": severity,
                    "title": title,
                    "detail": f"The response does not include the {header} header.",
                    "recommendation": recommendation,
                }
            )

    if normalized.get("access-control-allow-origin") == "*":
        findings.append(
            {
                "code": "cors_wildcard",
                "severity": "medium",
                "title": "Wildcard CORS origin",
                "detail": "The API allows browser requests from any origin.",
                "recommendation": "Restrict Access-Control-Allow-Origin to trusted origins; do not combine wildcard origins with credentials.",
            }
        )

    for header in ("server", "x-powered-by"):
        value = normalized.get(header)
        if value:
            findings.append(
                {
                    "code": f"technology_disclosure_{header.replace('-', '_')}",
                    "severity": "low",
                    "title": f"Technology disclosure in {header}",
                    "detail": f"The response identifies server technology ({value[:120]}).",
                    "recommendation": f"Remove or minimize the {header} response header where practical.",
                }
            )
    return findings
