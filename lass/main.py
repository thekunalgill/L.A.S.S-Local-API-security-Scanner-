from __future__ import annotations

import ipaddress
import os
import time
import uuid
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import urlsplit, urlunsplit

import httpx
from fastapi import FastAPI, HTTPException
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles

from .scanner import analyze_response, score_findings
from .schemas import ScanRequest, ScanResponse
from .security import (
    TargetValidationError,
    validate_public_target_url,
    validate_target_url,
)

WEB_MODE = os.getenv("VERCEL") == "1"


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


@app.get("/", include_in_schema=False)
def index() -> FileResponse:
    return FileResponse(STATIC_DIR / "index.html")


@app.get("/api/config")
def config() -> dict[str, bool]:
    return {"web_mode": WEB_MODE}


@app.get("/api/health")
def health() -> dict[str, str]:
    return {"status": "ok"}


@app.post("/api/scans", response_model=ScanResponse)
async def create_scan(request: ScanRequest) -> ScanResponse:
    try:
        if WEB_MODE:
            target, resolved_ip = validate_public_target_url(request.target_url)
        else:
            target = validate_target_url(request.target_url)
            resolved_ip = None
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
        return ScanResponse(
            id=uuid.uuid4().hex,
            target_url=target,
            status="failed",
            score=None,
            status_code=None,
            latency_ms=round((time.perf_counter() - started) * 1000, 2),
            findings=[],
            error=type(exc).__name__,
            timestamp=datetime.now(timezone.utc),
        )
    findings = analyze_response(status_code, headers, is_https)
    return ScanResponse(
        id=uuid.uuid4().hex,
        target_url=target,
        status="completed",
        score=score_findings(findings),
        status_code=status_code,
        latency_ms=latency_ms,
        findings=findings,
        error=None,
        timestamp=datetime.now(timezone.utc),
    )
