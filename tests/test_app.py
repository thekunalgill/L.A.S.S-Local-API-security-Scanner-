import os
import tempfile

import pytest
from fastapi.testclient import TestClient

TEST_DATABASE = os.path.join(tempfile.mkdtemp(prefix="lass-tests-"), "test.db")
os.environ["LASS_DATABASE_URL"] = f"sqlite:///{TEST_DATABASE}"
os.environ["LASS_ADMIN_USERNAME"] = "test-admin"
os.environ["LASS_ADMIN_PASSWORD"] = "test-only-password"

from app import Finding, app, build_findings, score_findings, validate_local_target


@pytest.mark.parametrize("target", [
    "http://localhost:8000/health",
    "http://127.0.0.1:8000/health",
    "http://[::1]:8000/health",
])
def test_accepts_loopback_targets(target):
    assert validate_local_target(target).endswith("/health")


@pytest.mark.parametrize("target", [
    "https://example.com/",
    "http://192.168.1.10:8000/",
    "http://127.0.0.1.example.com:8000/",
    "http://user:pass@localhost:8000/",
    "http://localhost/",
])
def test_rejects_nonlocal_or_ambiguous_targets(target):
    with pytest.raises(ValueError):
        validate_local_target(target)


def test_localhost_is_resolved_to_literal_loopback():
    assert validate_local_target("http://localhost:8000/health") == "http://127.0.0.1:8000/health"


def test_redirect_target_is_not_scanned():
    with TestClient(app, base_url="http://127.0.0.1", client=("127.0.0.1", 12345)) as client:
        login = client.post("/api/auth/login", json={"username": "test-admin", "password": "test-only-password"})
        assert login.status_code == 200
        response = client.post("/api/scans", json={"target": "https://example.com/"})
    assert response.status_code == 400


def test_rejects_non_loopback_client():
    with TestClient(app, base_url="http://127.0.0.1", client=("192.0.2.10", 12345)) as client:
        response = client.get("/")
    assert response.status_code == 403


def test_rejects_non_loopback_host_header():
    with TestClient(app, base_url="http://127.0.0.1", client=("127.0.0.1", 12345)) as client:
        response = client.get("/", headers={"Host": "attacker.example"})
    assert response.status_code == 403


def test_rejects_cross_origin_requests():
    with TestClient(app, base_url="http://127.0.0.1", client=("127.0.0.1", 12345)) as client:
        response = client.post(
            "/api/scans",
            headers={"Origin": "http://attacker.example"},
            json={"target": "http://127.0.0.1:8000/"},
        )
    assert response.status_code == 403


def test_login_creates_session_and_me_returns_user():
    with TestClient(app, base_url="http://127.0.0.1", client=("127.0.0.1", 12345)) as client:
        response = client.post("/api/auth/login", json={"username": "test-admin", "password": "test-only-password"})
        assert response.status_code == 200
        me = client.get("/api/auth/me")
    assert me.status_code == 200
    assert me.json()["username"] == "test-admin"


def test_login_rejects_bad_password():
    with TestClient(app, base_url="http://127.0.0.1", client=("127.0.0.1", 12345)) as client:
        response = client.post("/api/auth/login", json={"username": "test-admin", "password": "wrong"})
    assert response.status_code == 401


def test_dashboard_and_assets_are_served():
    with TestClient(app, base_url="http://127.0.0.1", client=("127.0.0.1", 12345)) as client:
        page = client.get("/")
        script = client.get("/static/app.js")
    assert page.status_code == 200
    assert "L.A.S.S." in page.text
    assert page.headers["content-security-policy"].startswith("default-src 'self'")
    assert page.headers["x-content-type-options"] == "nosniff"
    assert script.status_code == 200
    assert "loadHistory" in script.text


def test_scoring_is_capped_at_zero():
    findings = [Finding(severity="high", title="Test", detail="Test", recommendation="Test", deduction=150)]
    assert score_findings(findings) == 0


def test_clean_headers_and_fast_success_have_no_findings():
    import httpx

    headers = httpx.Headers({
        "x-content-type-options": "nosniff",
        "content-security-policy": "default-src 'self'",
        "strict-transport-security": "max-age=31536000",
    })
    assert build_findings(200, 30, headers) == []


def test_scans_are_linked_to_authenticated_user():
    with TestClient(app, base_url="http://127.0.0.1", client=("127.0.0.1", 12345)) as client:
        login = client.post("/api/auth/login", json={"username": "test-admin", "password": "test-only-password"})
        assert login.status_code == 200
        response = client.post("/api/scans", json={"target": "http://127.0.0.1:8000/"})
        assert response.status_code == 200
        history = client.get("/api/history")
        assert history.status_code == 200
        assert history.json()[0]["target"] == "http://127.0.0.1:8000/"