from __future__ import annotations

import hashlib
import hmac
import ipaddress
import json
import os
import secrets
import time
from asyncio import Semaphore
from contextlib import asynccontextmanager
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import urlsplit, urlunsplit

import httpx
from fastapi import Depends, FastAPI, HTTPException, Request
from fastapi.responses import FileResponse, JSONResponse, RedirectResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field, HttpUrl
from sqlalchemy import DateTime, Integer, String, Text, create_engine, select, text
from sqlalchemy.orm import DeclarativeBase, Mapped, Session, mapped_column, sessionmaker

BASE_DIR = Path(__file__).resolve().parent
DATABASE_URL = os.environ.get("LASS_DATABASE_URL", f"sqlite:///{BASE_DIR / 'lass.db'}")
engine = create_engine(DATABASE_URL, connect_args={"check_same_thread": False})
SessionLocal = sessionmaker(bind=engine, expire_on_commit=False)
MAX_CONCURRENT_SCANS = 4


class Base(DeclarativeBase):
    pass


class UserRecord(Base):
    __tablename__ = "users"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    username: Mapped[str] = mapped_column(String(120), unique=True, index=True)
    password_hash: Mapped[str] = mapped_column(String(255))
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc), index=True)


class SessionRecord(Base):
    __tablename__ = "sessions"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    session_id: Mapped[str] = mapped_column(String(255), unique=True, index=True)
    user_id: Mapped[int] = mapped_column(Integer, index=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc), index=True)


class ScanRecord(Base):
    __tablename__ = "scans"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    user_id: Mapped[int | None] = mapped_column(Integer, nullable=True, index=True)
    target: Mapped[str] = mapped_column(String(2048))
    status_code: Mapped[int | None] = mapped_column(Integer, nullable=True)
    latency_ms: Mapped[float | None] = mapped_column(nullable=True)
    score: Mapped[int] = mapped_column(Integer)
    findings_json: Mapped[str] = mapped_column(Text)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), index=True)


@asynccontextmanager
async def lifespan(_: FastAPI):
    ensure_database_schema()
    with SessionLocal() as db:
        ensure_default_user_record(db)
    app.state.http_client = httpx.AsyncClient(
        timeout=httpx.Timeout(5.0, connect=2.0),
        follow_redirects=False,
        trust_env=False,
        limits=httpx.Limits(max_connections=MAX_CONCURRENT_SCANS, max_keepalive_connections=MAX_CONCURRENT_SCANS),
    )
    app.state.scan_slots = Semaphore(MAX_CONCURRENT_SCANS)
    yield
    await app.state.http_client.aclose()


app = FastAPI(title="L.A.S.S.", description="Local API health and security checks", lifespan=lifespan)
app.mount("/static", StaticFiles(directory=BASE_DIR / "static"), name="static")


def is_loopback_host(host: str | None) -> bool:
    if not host:
        return False
    hostname = host.strip("[]").rstrip(".").lower()
    if hostname == "localhost":
        return True
    try:
        return ipaddress.ip_address(hostname).is_loopback
    except ValueError:
        return False


@app.middleware("http")
async def protect_local_interface(request, call_next):
    client_host = request.client.host if request.client else None
    request_host = urlsplit(f"//{request.headers.get('host', '')}").hostname
    origin = request.headers.get("origin")
    if not is_loopback_host(client_host) or not is_loopback_host(request_host):
        return JSONResponse(status_code=403, content={"detail": "L.A.S.S. is restricted to loopback connections"})
    if origin:
        origin_parts = urlsplit(origin)
        if origin_parts.netloc.lower() != request.headers.get("host", "").lower():
            return JSONResponse(status_code=403, content={"detail": "Cross-origin requests are not allowed"})
    response = await call_next(request)
    response.headers["Content-Security-Policy"] = "default-src 'self'; style-src 'self'; font-src 'self'; img-src 'self' data:; script-src 'self'; connect-src 'self'; object-src 'none'; base-uri 'none'; frame-ancestors 'none'; form-action 'self'"
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["Referrer-Policy"] = "no-referrer"
    response.headers["Permissions-Policy"] = "camera=(), microphone=(), geolocation=()"
    response.headers["Cache-Control"] = "no-store"
    return response


def hash_password(password: str) -> str:
    salt = secrets.token_bytes(16)
    iterations = 310_000
    digest = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, iterations)
    return f"pbkdf2_sha256${iterations}${salt.hex()}${digest.hex()}"


def verify_password(password: str, stored_hash: str) -> bool:
    try:
        algorithm, iteration_text, salt_hex, digest_hex = stored_hash.split("$", 3)
        if algorithm != "pbkdf2_sha256":
            return False
        digest = hashlib.pbkdf2_hmac(
            "sha256", password.encode("utf-8"), bytes.fromhex(salt_hex), int(iteration_text)
        )
        return hmac.compare_digest(digest.hex(), digest_hex)
    except (ValueError, TypeError):
        return False


def get_db():
    with SessionLocal() as session:
        yield session


def get_session_id(request: Request) -> str | None:
    return request.cookies.get("lass_session")


def get_current_user(request: Request, db: Session = Depends(get_db)) -> UserRecord:
    session_id = get_session_id(request)
    if not session_id:
        raise HTTPException(status_code=401, detail="Authentication required")
    session = db.scalar(select(SessionRecord).where(SessionRecord.session_id == session_id))
    if not session:
        raise HTTPException(status_code=401, detail="Invalid session")
    user = db.get(UserRecord, session.user_id)
    if not user:
        raise HTTPException(status_code=401, detail="User not found")
    return user


class LoginRequest(BaseModel):
    username: str = Field(min_length=1, max_length=120)
    password: str = Field(min_length=1, max_length=255)


class AuthUser(BaseModel):
    id: int
    username: str


class ScanRequest(BaseModel):
    target: HttpUrl = Field(max_length=2048)


class Finding(BaseModel):
    severity: str
    title: str
    detail: str
    recommendation: str
    deduction: int


class ScanResult(BaseModel):
    id: int
    target: str
    status_code: int | None
    latency_ms: float | None
    score: int
    findings: list[Finding]
    created_at: datetime


class ScanSummary(BaseModel):
    id: int
    target: str
    status_code: int | None
    latency_ms: float | None
    score: int
    created_at: datetime


def validate_local_target(target: str) -> str:
    """Accept only literal loopback IPs or the exact localhost hostname."""
    parsed = urlsplit(target)
    if parsed.scheme not in {"http", "https"} or not parsed.hostname:
        raise ValueError("Use an http:// or https:// URL with a localhost address.")
    if parsed.username is not None or parsed.password is not None:
        raise ValueError("URLs containing credentials are not allowed.")
    hostname = parsed.hostname.rstrip(".").lower()
    is_loopback = hostname == "localhost"
    normalized_host = "127.0.0.1" if is_loopback else hostname
    if not is_loopback:
        try:
            address = ipaddress.ip_address(hostname)
            is_loopback = address.is_loopback
            normalized_host = address.compressed
        except ValueError:
            is_loopback = False
    if not is_loopback:
        raise ValueError("L.A.S.S. only scans localhost and loopback IP addresses.")
    if parsed.port is None:
        raise ValueError("Include the local API port, for example http://127.0.0.1:8000.")
    if ":" in normalized_host:
        normalized_host = f"[{normalized_host}]"
    netloc = f"{normalized_host}:{parsed.port}"
    return urlunsplit((parsed.scheme, netloc, parsed.path or "/", parsed.query, ""))


def build_findings(status_code: int | None, latency_ms: float | None, headers: httpx.Headers | None, error: str | None = None) -> list[Finding]:
    findings: list[Finding] = []
    if error:
        findings.append(Finding(
            severity="high", title="API did not respond", detail=error,
            recommendation="Confirm the local API is running and the URL and port are correct.", deduction=35,
        ))
    elif status_code is not None and status_code >= 500:
        findings.append(Finding(
            severity="high", title="Server error response", detail=f"The endpoint returned HTTP {status_code}.",
            recommendation="Inspect the API logs and handle this request without returning a server error.", deduction=25,
        ))
    elif status_code is not None and status_code >= 400:
        findings.append(Finding(
            severity="medium", title="Client error response", detail=f"The endpoint returned HTTP {status_code}.",
            recommendation="Check whether this endpoint is expected to be unauthenticated and document its response behavior.", deduction=10,
        ))

    if latency_ms is not None and latency_ms > 1000:
        findings.append(Finding(
            severity="medium", title="High response latency", detail=f"Response took {latency_ms:.0f} ms (threshold: 1000 ms).",
            recommendation="Profile the handler and its dependencies; consider caching or reducing synchronous work.", deduction=10,
        ))

    if headers is not None:
        checks = [
            ("x-content-type-options", "Missing content type protection", "Add X-Content-Type-Options: nosniff to reduce MIME-sniffing risk.", 5),
            ("content-security-policy", "Missing content security policy", "Define a Content-Security-Policy appropriate for any browser-facing API responses.", 5),
            ("strict-transport-security", "Missing transport security policy", "Enable HTTPS and add Strict-Transport-Security in deployments that terminate TLS.", 5),
        ]
        for header, title, recommendation, deduction in checks:
            if header not in headers:
                findings.append(Finding(
                    severity="low", title=title,
                    detail=f"The response does not include {header}.",
                    recommendation=recommendation, deduction=deduction,
                ))
    return findings


def score_findings(findings: list[Finding]) -> int:
    return max(0, 100 - sum(finding.deduction for finding in findings))


def result_from_record(record: ScanRecord) -> ScanResult:
    import json

    return ScanResult(
        id=record.id, target=record.target, status_code=record.status_code,
        latency_ms=record.latency_ms, score=record.score,
        findings=[Finding(**item) for item in json.loads(record.findings_json)],
        created_at=record.created_at,
    )


def ensure_default_user_record(db: Session) -> None:
    username = os.environ.get("LASS_ADMIN_USERNAME")
    existing = db.scalar(select(UserRecord).where(UserRecord.username == username)) if username else None
    if existing is None:
        password = os.environ.get("LASS_ADMIN_PASSWORD")
        if not username or not password:
            raise RuntimeError("Set LASS_ADMIN_USERNAME and LASS_ADMIN_PASSWORD before starting L.A.S.S.")
        db.add(UserRecord(username=username, password_hash=hash_password(password)))
        db.commit()


def ensure_database_schema() -> None:
    Base.metadata.create_all(engine)
    with engine.begin() as conn:
        scans_columns = conn.execute(text("PRAGMA table_info(scans)")).fetchall()
        if not any(column[1] == "user_id" for column in scans_columns):
            conn.execute(text("ALTER TABLE scans ADD COLUMN user_id INTEGER"))


ensure_database_schema()


@app.get("/", include_in_schema=False)
def home():
    return FileResponse(BASE_DIR / "static" / "index.html")


@app.post("/api/auth/login")
def login(payload: LoginRequest, request: Request, db: Session = Depends(get_db)):
    user = db.scalar(select(UserRecord).where(UserRecord.username == payload.username))
    if user is None or not verify_password(payload.password, user.password_hash):
        raise HTTPException(status_code=401, detail="Invalid username or password")

    session_id = secrets.token_urlsafe(32)
    db.add(SessionRecord(session_id=session_id, user_id=user.id))
    db.commit()

    response = JSONResponse({"id": user.id, "username": user.username})
    response.set_cookie(key="lass_session", value=session_id, httponly=True, samesite="lax", secure=False, path="/")
    return response


@app.post("/api/auth/logout")
def logout(request: Request, db: Session = Depends(get_db)):
    session_id = get_session_id(request)
    if session_id:
        db.query(SessionRecord).filter(SessionRecord.session_id == session_id).delete()
        db.commit()
    response = JSONResponse({"ok": True})
    response.delete_cookie(key="lass_session", path="/")
    return response


@app.get("/api/auth/me", response_model=AuthUser)
def me(current_user: UserRecord = Depends(get_current_user)):
    return AuthUser(id=current_user.id, username=current_user.username)


@app.get("/api/history", response_model=list[ScanSummary])
def history(current_user: UserRecord = Depends(get_current_user), db: Session = Depends(get_db)):
    records = db.scalars(select(ScanRecord).where(ScanRecord.user_id == current_user.id).order_by(ScanRecord.created_at.desc()).limit(50)).all()
    return records


@app.get("/api/scans/{scan_id}", response_model=ScanResult)
def scan_detail(scan_id: int, current_user: UserRecord = Depends(get_current_user), db: Session = Depends(get_db)):
    record = db.get(ScanRecord, scan_id)
    if record is None or record.user_id != current_user.id:
        raise HTTPException(status_code=404, detail="Scan not found")
    return result_from_record(record)


@app.post("/api/scans", response_model=ScanResult)
async def create_scan(request: ScanRequest, current_user: UserRecord = Depends(get_current_user), db: Session = Depends(get_db)):
    try:
        target = validate_local_target(str(request.target))
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc

    status_code = None
    latency_ms = None
    headers = None
    error = None
    try:
        async with app.state.scan_slots:
            started = time.perf_counter()
            async with app.state.http_client.stream("GET", target) as response:
                latency_ms = round((time.perf_counter() - started) * 1000, 2)
                status_code = response.status_code
                headers = response.headers
                if 300 <= status_code < 400:
                    error = "The endpoint redirected; redirects are not followed by this scanner."
    except httpx.TimeoutException:
        error = "The local endpoint timed out after 5 seconds."
    except httpx.HTTPError as exc:
        error = f"Could not connect to the local endpoint ({type(exc).__name__})."

    findings = build_findings(status_code, latency_ms, headers, error)
    record = ScanRecord(
        user_id=current_user.id,
        target=target, status_code=status_code, latency_ms=latency_ms,
        score=score_findings(findings), findings_json=json.dumps([item.model_dump() for item in findings]),
        created_at=datetime.now(timezone.utc),
    )
    db.add(record)
    db.commit()
    db.refresh(record)
    return result_from_record(record)