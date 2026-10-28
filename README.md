# L.A.S.S. (Local API Security Scanner)

Local API Security Scanner (L.A.S.S.), a lightweight pre-deployment API health and security gatekeeper for local developer testing.

L.A.S.S. is a local pre-deployment check for an API running on the same machine. It makes one read-only `GET` request, records response health and latency, checks a small set of baseline response headers, calculates a score out of 100, and saves the result for later comparison.

This is a baseline health and configuration checker, not a penetration-testing or OWASP vulnerability scanner. It does not send attack payloads, crawl endpoints, test authentication, or follow redirects.

## Run locally

Python 3.10 or later is recommended. From the project folder:

```bash
python3 -m venv .venv
.venv/bin/python -m pip install -r requirements.txt
export LASS_ADMIN_USERNAME='your-admin-name'
export LASS_ADMIN_PASSWORD='use-a-long-unique-password'
.venv/bin/uvicorn app:app --host 127.0.0.1 --port 8000
```

The first account is created from `LASS_ADMIN_USERNAME` and `LASS_ADMIN_PASSWORD`. Passwords are stored as salted PBKDF2 hashes. Never commit actual credentials or `.env` files. Open <http://127.0.0.1:8000>. The API schema is available at <http://127.0.0.1:8000/docs>.

L.A.S.S. is intentionally restricted to loopback clients and targets. It is not designed for public hosting; do not bind it to a public interface or deploy it as an internet-facing service. A private local machine or isolated development environment is the intended runtime.

Run the test suite with:

```bash
.venv/bin/python -m pytest -q
```

## Repository map

| Path | Responsibility |
| --- | --- |
| `app.py` | FastAPI routes, request/response schemas, local-target validation, asynchronous HTTP request, findings, scoring, and SQLAlchemy persistence. |
| `static/index.html` | Dashboard structure and scan/history controls. |
| `static/style.css` | Responsive visual design, status and severity styles, and layout. |
| `static/app.js` | Browser-side scan submission, result rendering, history loading, and detail lookup. User-visible API data is HTML-escaped before insertion. |
| `tests/test_app.py` | Tests for local target acceptance/rejection, score bounds, and dashboard assets. |
| `requirements.txt` | Python runtime and test dependencies. |
| `.env.example` | Names the required configuration settings with empty values only. |
| `.gitignore` | Excludes local environments, credentials, private keys, test caches, Python bytecode, and database files. |
| `lass.db` | Created on first app startup; stores scan history and is intentionally not tracked. |

## Request flow

1. The dashboard submits a target URL as JSON to `POST /api/scans`.
2. Pydantic parses the request. `validate_local_target()` then checks scheme, credentials, hostname, loopback address, and explicit port. Rejected targets return HTTP 400 before any outbound request is made.
3. A shared, connection-limited `httpx.AsyncClient` sends one `GET` with proxy environment settings disabled, a bounded timeout, and redirect-following disabled. Response bodies are never read.
4. The response status, elapsed time, and selected headers go to `build_findings()`. Connection and timeout failures become findings rather than uncaught errors.
5. `score_findings()` subtracts each finding's deduction from 100 and clamps the result at zero.
6. SQLAlchemy stores the report in local SQLite. The dashboard receives the report and refreshes the recent scans table.

## API routes

| Method and route | Purpose |
| --- | --- |
| `GET /` | Serve the dashboard. |
| `GET /api/history` | Return up to 50 most recent scan summaries. |
| `GET /api/scans/{scan_id}` | Return one saved scan, including findings and recommendations. |
| `POST /api/scans` | Validate and scan one local URL, then save and return the report. |
| `/docs` | Interactive API documentation provided by FastAPI. |

## Methods and scoring

### Target validation

`validate_local_target(target)` accepts `localhost` or a literal IP address that Python's `ipaddress` module identifies as loopback, and requires `http` or `https` plus a port. It rejects credentials, hostnames that merely contain `localhost`, and other local-network or public addresses. `localhost` is rewritten to `127.0.0.1` before connecting, avoiding host-resolution ambiguity. The HTTP client does not follow redirects or read response bodies. Middleware also requires a loopback client and Host header and rejects mismatched browser Origins.

### Baseline checks

| Finding | Severity | Deduction |
| --- | --- | ---: |
| Local API cannot be reached or times out | High | 35 |
| HTTP 5xx response | High | 25 |
| HTTP 4xx response | Medium | 10 |
| Response takes more than 1000 ms | Medium | 10 |
| Missing `X-Content-Type-Options` | Low | 5 |
| Missing `Content-Security-Policy` | Low | 5 |
| Missing `Strict-Transport-Security` | Low | 5 |

The initial score is 100. Deductions are added and the result is clamped to the range 0–100. A finding includes a short explanation and suggested remediation. Header recommendations are signals to review, not universal requirements: for example, HSTS matters when HTTPS is configured, and CSP is most useful for browser-consumed content.

## Technologies

- **Python** provides the backend implementation and standard-library URL/IP parsing.
- **FastAPI** supplies HTTP routing, OpenAPI documentation, dependency injection, and Pydantic request/response validation.
- **HTTPX** performs the bounded asynchronous request to the selected local endpoint.
- **Pydantic** validates API inputs and structures findings and scan responses.
- **SQLAlchemy ORM** maps scan history to a SQLite table.
- **SQLite** persists history in a single local database file without a separate database server.
- **HTML, CSS, and browser JavaScript** provide the dashboard without a separate frontend build system or third-party asset requests.
- **pytest** runs the behavior and route tests.

## Scope and known limitations

- Only a single URL and its response are checked; the scanner does not discover an API's route list or OpenAPI schema.
- A score is a transparent project baseline, not a certification or comprehensive security rating.
- The latency threshold is fixed at one second, and only three response headers are checked.
- Health and security-header conclusions depend on the response from the chosen route; an application may set different headers on different routes.
- SQLite history is local to this checkout; the app provides login-protected per-user scan history. Keep the server bound to `127.0.0.1` because the interface intentionally rejects non-loopback peers.
- A local service bound to `localhost` or a loopback address is accepted by design; scans of an explicitly authorized LAN target are not implemented.
