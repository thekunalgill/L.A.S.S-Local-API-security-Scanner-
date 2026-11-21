from __future__ import annotations

import ipaddress
import socket
from urllib.parse import urlsplit, urlunsplit


class TargetValidationError(ValueError):
    pass


_LOOPBACKS = {ipaddress.ip_address("127.0.0.1"), ipaddress.ip_address("::1")}
_PRIVATE_NETWORKS = (
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
)


def _is_allowed(address: ipaddress.IPv4Address | ipaddress.IPv6Address) -> bool:
    return address in _LOOPBACKS or (
        address.version == 4
        and any(address in network for network in _PRIVATE_NETWORKS)
    )


def validate_local_target_url(value: str) -> tuple[str, str]:
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
    if not host or "%" in host:
        raise TargetValidationError("The target host is invalid.")
    try:
        address = ipaddress.ip_address(host)
    except ValueError:
        try:
            host = host.encode("idna").decode("ascii")
            resolved = socket.getaddrinfo(
                host,
                port or (443 if parsed.scheme.lower() == "https" else 80),
                type=socket.SOCK_STREAM,
            )
            addresses = [ipaddress.ip_address(item[4][0]) for item in resolved]
        except (OSError, UnicodeError, ValueError, IndexError, TypeError) as exc:
            raise TargetValidationError(
                "The host could not be resolved safely."
            ) from exc
        if not addresses:
            raise TargetValidationError("The host did not resolve to an IP address.")
        if any(not _is_allowed(item) for item in addresses):
            raise TargetValidationError(
                "Only localhost and private LAN addresses are allowed. Public targets are blocked."
            )
        address = addresses[0]
    else:
        if not _is_allowed(address):
            raise TargetValidationError(
                "Only localhost and private LAN addresses are allowed. Public targets are blocked."
            )
        host = str(address)

    display_host = f"[{host}]" if ":" in host else host
    netloc = display_host if port is None else f"{display_host}:{port}"
    normalized = urlunsplit(
        (parsed.scheme.lower(), netloc, parsed.path or "/", parsed.query, "")
    )
    return normalized, str(address)