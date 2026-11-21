from unittest.mock import patch

import pytest

from lass.target_gate import TargetValidationError, validate_local_target_url


@pytest.mark.parametrize(
    ("target", "expected_ip"),
    [
        ("http://127.0.0.1:8000", "127.0.0.1"),
        ("http://[::1]:8000", "::1"),
        ("http://192.168.1.5:8000", "192.168.1.5"),
        ("http://10.0.0.2:8000", "10.0.0.2"),
    ],
)
def test_allows_explicit_local_and_private_targets(target, expected_ip):
    normalized, resolved_ip = validate_local_target_url(target)

    assert normalized == target + "/"
    assert resolved_ip == expected_ip


@patch("lass.target_gate.socket.getaddrinfo")
def test_allows_localhost_when_all_dns_answers_are_loopback(resolve):
    resolve.return_value = [
        (None, None, None, None, ("127.0.0.1", 80)),
        (None, None, None, None, ("::1", 80, 0, 0)),
    ]

    assert validate_local_target_url("http://localhost/") == (
        "http://localhost/",
        "127.0.0.1",
    )


@pytest.mark.parametrize(
    "target",
    [
        "http://8.8.8.8/",
        "http://127.0.0.2/",
        "http://127.0.0.1@evil.com/",
        "ftp://127.0.0.1/",
    ],
)
def test_rejects_public_ip_credentials_and_unsupported_scheme(target):
    with pytest.raises(TargetValidationError):
        validate_local_target_url(target)


@patch("lass.target_gate.socket.getaddrinfo")
def test_rejects_hostname_resolving_to_public_ip(resolve):
    resolve.return_value = [(None, None, None, None, ("8.8.8.8", 443))]

    with pytest.raises(TargetValidationError, match="Public targets are blocked"):
        validate_local_target_url("https://example.com/")


@patch("lass.target_gate.socket.getaddrinfo")
def test_checks_every_hostname_dns_answer(resolve):
    resolve.return_value = [
        (None, None, None, None, ("192.168.1.8", 443)),
        (None, None, None, None, ("93.184.216.34", 443)),
    ]

    with pytest.raises(TargetValidationError, match="Public targets are blocked"):
        validate_local_target_url("https://api.home/")