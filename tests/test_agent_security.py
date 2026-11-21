from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from threading import Thread

from fastapi.testclient import TestClient
import pytest

from lass.main import _allowed_origin, app


def make_client(monkeypatch, tmp_path):
    monkeypatch.setenv("LASS_DB_PATH", str(tmp_path / "agent.sqlite3"))
    return TestClient(app)


@pytest.mark.parametrize("origin", ["http://localhost", "http://localhost:5173"])
def test_allows_localhost_development_origins(origin):
    assert _allowed_origin(origin)


def test_allowed_origin_private_network_preflight(monkeypatch, tmp_path):
    client = make_client(monkeypatch, tmp_path)
    origin = "https://l-a-s-s-local-api-security-scanner.vercel.app"

    with client:
        response = client.options(
            "/api/scans",
            headers={
                "Origin": origin,
                "Access-Control-Request-Method": "POST",
                "Access-Control-Request-Headers": "content-type,x-lass-token",
                "Access-Control-Request-Private-Network": "true",
            },
        )

    assert response.status_code == 204
    assert response.headers["access-control-allow-origin"] == origin
    assert response.headers["access-control-allow-private-network"] == "true"


def test_rejects_untrusted_origin(monkeypatch, tmp_path):
    client = make_client(monkeypatch, tmp_path)

    with client:
        response = client.get("/api/health", headers={"Origin": "https://evil.example"})

    assert response.status_code == 403


def test_scan_requires_pairing_token_and_authorization(monkeypatch, tmp_path):
    client = make_client(monkeypatch, tmp_path)

    with client:
        token = app.state.pairing_token
        missing_token = client.post(
            "/api/scans",
            json={"target_url": "http://127.0.0.1:8000", "authorized": True},
        )
        missing_consent = client.post(
            "/api/scans",
            headers={"X-LASS-Token": token},
            json={"target_url": "http://127.0.0.1:8000", "authorized": False},
        )
        invalid_token = client.post(
            "/api/scans",
            headers={"X-LASS-Token": "not-the-pairing-token"},
            json={"target_url": "http://127.0.0.1:8000", "authorized": True},
        )

    assert missing_token.status_code == 401
    assert missing_consent.status_code == 400
    assert "permission" in missing_consent.json()["detail"]
    assert invalid_token.status_code == 401


def test_public_target_is_rejected_before_httpx(monkeypatch, tmp_path):
    client = make_client(monkeypatch, tmp_path)

    with client:
        response = client.post(
            "/api/scans",
            headers={"X-LASS-Token": app.state.pairing_token},
            json={"target_url": "http://8.8.8.8/", "authorized": True},
        )

    assert response.status_code == 400
    assert "Public targets are blocked" in response.json()["detail"]


def test_public_redirect_is_not_followed(monkeypatch, tmp_path):
    class RedirectHandler(BaseHTTPRequestHandler):
        requests = 0

        def do_GET(self):
            type(self).requests += 1
            self.send_response(302)
            self.send_header("Location", "http://8.8.8.8/")
            self.end_headers()

        def log_message(self, format, *args):
            pass

    server = ThreadingHTTPServer(("127.0.0.1", 0), RedirectHandler)
    thread = Thread(target=server.serve_forever, daemon=True)
    thread.start()
    client = make_client(monkeypatch, tmp_path)
    try:
        with client:
            response = client.post(
                "/api/scans",
                headers={"X-LASS-Token": app.state.pairing_token},
                json={
                    "target_url": f"http://127.0.0.1:{server.server_port}/redirect",
                    "authorized": True,
                },
            )
    finally:
        server.shutdown()
        thread.join()
        server.server_close()

    assert response.status_code == 200
    assert response.json()["status_code"] == 302
    assert RedirectHandler.requests == 1