from __future__ import annotations

import ipaddress
import socket
from urllib.parse import urlsplit, urlunsplit


class TargetValidationError(ValueError):
    pass


def _validate_target_url(value: str, *, public_only: bool) -> tuple[str, str | None]:
    target = value.strip()
    if not target or any(ord(char) < 32 for char in target):
        raise TargetValidationError("Enter a valid HTTP or HTTPS URL.")
    try:
        parsed = urlsplit(target)
        port = parsed.port
    except ValueError as exc:
        raise TargetValidationError("The URL or port is invalid.") from exc
    if parsed.scheme.lower() not in {"http", "https"}:
        raise TargetValidationError("Only HTTP and HTTPS targets are supported.")
    if not parsed.hostname or not parsed.netloc:
        raise TargetValidationError("Enter a URL that includes a host.")
    if parsed.username is not None or parsed.password is not None:
        raise TargetValidationError("Credentials in target URLs are not allowed.")
    if parsed.fragment:
        raise TargetValidationError("URL fragments are not supported.")
    if port is not None and not 1 <= port <= 65535:
        raise TargetValidationError("The port must be between 1 and 65535.")

    host = parsed.hostname.rstrip(".").lower()
    if public_only:
        try:
            addresses = [ipaddress.ip_address(host)]
        except ValueError:
            try:
                resolved = socket.getaddrinfo(
                    host,
                    port or (443 if parsed.scheme.lower() == "https" else 80),
                    type=socket.SOCK_STREAM,
                )
                addresses = [ipaddress.ip_address(item[4][0]) for item in resolved]
            except (OSError, ValueError) as exc:
                raise TargetValidationError("The host could not be resolved safely.") from exc
            if not addresses:
                raise TargetValidationError("The host did not resolve to an IP address.")
        if any(not address.is_global for address in addresses):
            raise TargetValidationError("Hosted scans are restricted to public IP addresses.")
        if ":" in host:
            host = str(ipaddress.ip_address(host))
    elif host == "localhost":
        host = "127.0.0.1"
    else:
        try:
            address = ipaddress.ip_address(host)
        except ValueError as exc:
            raise TargetValidationError(
                "Only localhost or loopback IPs are allowed. Private LAN addresses and public hosts are blocked."
            ) from exc
        allowed_networks = (
            (
                ipaddress.ip_network("10.0.0.0/8"),
                ipaddress.ip_network("172.16.0.0/12"),
                ipaddress.ip_network("192.168.0.0/16"),
            )
            if address.version == 4
            else (ipaddress.ip_network("fc00::/7"),)
        )
        if not address.is_loopback and not any(
            address in network for network in allowed_networks
        ):
            raise TargetValidationError(
                "Only localhost, loopback IPs, or private LAN IPs are allowed. Public hosts are blocked."
            )
        host = str(address)

    display_host = f"[{host}]" if ":" in host else host
    netloc = display_host if port is None else f"{display_host}:{port}"
    normalized = urlunsplit(
        (parsed.scheme.lower(), netloc, parsed.path or "/", parsed.query, "")
    )
    resolved_ip = str(addresses[0]) if public_only else None
    return normalized, resolved_ip


def validate_target_url(value: str) -> str:
    normalized, _ = _validate_target_url(value, public_only=False)
    return normalized


def validate_public_target_url(value: str) -> tuple[str, str]:
    normalized, resolved_ip = _validate_target_url(value, public_only=True)
    if resolved_ip is None:
        raise TargetValidationError("The host could not be resolved safely.")
    return normalized, resolved_ip
