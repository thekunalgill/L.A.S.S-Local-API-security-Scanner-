from __future__ import annotations

import ipaddress
import os
import secrets
import time
import uuid
from collections import defaultdict, deque
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import urlsplit, urlunsplit

import httpx
from fastapi import FastAPI, Header, HTTPException, Request
from fastapi.responses import FileResponse, JSONResponse, Response
from fastapi.staticfiles import StaticFiles

from .scanner import analyze_response
from .scoring import score_findings
from .schemas import ScanRequest, ScanResponse
from .storage import ScanStorage
from .target_gate import TargetValidationError, validate_local_target_url


def resource_path(relative_path: str) -> Path:
    import sys

    bundle_dir = Path(getattr(sys, "_MEIPASS", Path(__file__).resolve().parent.parent))
    return bundle_dir / relative_path


STATIC_DIR = resource_path("static")


def pinned_request_target(target: str, resolved_ip: str | None) -> tuple[str, dict[str, str], dict[str, str]]:
    if resolved_ip is None:
        return target, {}, {}

    parsed = urlsplit(target)
    original_host = parsed.hostname or ""
    try:
        ipaddress.ip_address(original_host)
        tls_hostname = None
    except ValueError:
        original_host = original_host.encode("idna").decode("ascii")
        tls_hostname = original_host if parsed.scheme == "https" else None

    host_header = f"[{original_host}]" if ":" in original_host else original_host
    connect_host = f"[{resolved_ip}]" if ":" in resolved_ip else resolved_ip
    if parsed.port is not None:
        host_header = f"{host_header}:{parsed.port}"
        connect_host = f"{connect_host}:{parsed.port}"
    request_url = urlunsplit(
        (parsed.scheme, connect_host, parsed.path, parsed.query, "")
    )
    extensions = {"sni_hostname": tls_hostname} if tls_hostname else {}
    return request_url, {"Host": host_header}, extensions


app = FastAPI(
    title="L.A.S.S.",
    description="An API health and security baseline scanner.",
    version="1.0.0",
)
app.mount("/static", StaticFiles(directory=STATIC_DIR), name="static")


def _allowed_origin(origin: str) -> bool:
    configured_origin = os.getenv(
        "LASS_ALLOWED_ORIGIN",
        "https://l-a-s-s-local-api-security-scanner.vercel.app",
    ).rstrip("/")
    if origin == configured_origin:
        return True
    try:
        parsed = urlsplit(origin)
        return (
            parsed.scheme == "http"
            and parsed.hostname == "localhost"
            and parsed.username is None
            and parsed.password is None
            and not parsed.path
            and not parsed.query
            and not parsed.fragment
            and (parsed.port is None or 1 <= parsed.port <= 65535)
        )
    except ValueError:
        return False


class AgentOriginMiddleware:
    def __init__(self, application):
        self.application = application

    async def __call__(self, scope, receive, send):
        if scope["type"] != "http":
            await self.application(scope, receive, send)
            return

        headers = {key.lower(): value for key, value in scope["headers"]}
        origin = headers.get(b"origin", b"").decode("latin-1")
        if origin and not _allowed_origin(origin):
            response = JSONResponse(
                {"detail": "Origin is not allowed."}, status_code=403
            )
            await response(scope, receive, send)
            return

        is_preflight = (
            scope["method"] == "OPTIONS"
            and b"access-control-request-method" in headers
        )
        if is_preflight:
            requested_method = headers[b"access-control-request-method"].decode(
                "latin-1"
            ).upper()
            if not origin or requested_method not in {"GET", "POST"}:
                response = JSONResponse(
                    {"detail": "Preflight request is not allowed."}, status_code=403
                )
                await response(scope, receive, send)
                return
            response_headers = {
                "Access-Control-Allow-Origin": origin,
                "Access-Control-Allow-Methods": "GET, POST, OPTIONS",
                "Access-Control-Allow-Headers": "Content-Type, X-LASS-Token",
                "Access-Control-Max-Age": "600",
                "Access-Control-Allow-Private-Network": "true",
                "Vary": "Origin",
            }
            response = Response(status_code=204, headers=response_headers)
            await response(scope, receive, send)
            return

        async def send_with_cors(message):
            if origin and message["type"] == "http.response.start":
                response_headers = list(message.get("headers", []))
                response_headers.extend(
                    [
                        (b"access-control-allow-origin", origin.encode("latin-1")),
                        (b"vary", b"Origin"),
                    ]
                )
                message["headers"] = response_headers
            await send(message)

        await self.application(scope, receive, send_with_cors)


app.add_middleware(AgentOriginMiddleware)


@app.on_event("startup")
async def initialize_agent() -> None:
    app.state.pairing_token = secrets.token_urlsafe(32)
    app.state.scan_storage = ScanStorage()
    app.state.scan_rate = defaultdict(deque)
    print(f"L.A.S.S. pairing token: {app.state.pairing_token}", flush=True)


def _require_token(token: str | None) -> None:
    if not token or not secrets.compare_digest(
        token, getattr(app.state, "pairing_token", "")
    ):
        raise HTTPException(status_code=401, detail="A valid agent pairing token is required.")


async def _check_rate_limit(request: Request) -> None:
    now = time.monotonic()
    client_host = request.client.host if request.client else "unknown"
    events = app.state.scan_rate[client_host]
    while events and now - events[0] >= 60:
        events.popleft()
    if len(events) >= 10:
        raise HTTPException(
            status_code=429,
            detail="Scan rate limit reached. Wait a minute before trying again.",
        )
    events.append(now)


@app.get("/", include_in_schema=False)
def index() -> FileResponse:
    return FileResponse(STATIC_DIR / "index.html")


@app.get("/api/health")
def health() -> dict[str, str]:
    return {"status": "ok"}


@app.get("/api/history", response_model=list[ScanResponse])
def scan_history(x_lass_token: str | None = Header(default=None)) -> list[ScanResponse]:
    _require_token(x_lass_token)
    return app.state.scan_storage.recent()


@app.post("/api/scans", response_model=ScanResponse)
async def create_scan(
    request: ScanRequest,
    http_request: Request,
    x_lass_token: str | None = Header(default=None),
) -> ScanResponse:
    _require_token(x_lass_token)
    if not request.authorized:
        raise HTTPException(
            status_code=400,
            detail="Confirm that you own or have permission to test this target.",
        )
    await _check_rate_limit(http_request)
    try:
        target, resolved_ip = validate_local_target_url(request.target_url)
    except TargetValidationError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc

    request_url, request_headers, request_extensions = pinned_request_target(
        target, resolved_ip
    )
    started = time.perf_counter()
    try:
        async with httpx.AsyncClient(
            timeout=httpx.Timeout(8.0), follow_redirects=False, trust_env=False
        ) as client:
            async with client.stream(
                "GET",
                request_url,
                headers=request_headers,
                extensions=request_extensions,
            ) as response:
                status_code = response.status_code
                headers = dict(response.headers)
                is_https = response.request.url.scheme == "https"
                latency_ms = round((time.perf_counter() - started) * 1000, 2)
    except httpx.RequestError as exc:
        return app.state.scan_storage.save(ScanResponse(
            id=uuid.uuid4().hex,
            target_url=target,
            status="failed",
            score=None,
            status_code=None,
            latency_ms=round((time.perf_counter() - started) * 1000, 2),
            findings=[],
            error=type(exc).__name__,
            timestamp=datetime.now(timezone.utc),
        ))
    findings = analyze_response(status_code, headers, is_https)
    return app.state.scan_storage.save(ScanResponse(
        id=uuid.uuid4().hex,
        target_url=target,
        status="completed",
        score=score_findings(findings),
        status_code=status_code,
        latency_ms=latency_ms,
        findings=findings,
        error=None,
        timestamp=datetime.now(timezone.utc),
    ))
