# L.A.S.S. — Local API Security Scanner

L.A.S.S. checks the response health and baseline security headers of local APIs. The Vercel deployment serves only the static web interface. All scans run through a FastAPI agent on your own computer, and the server rejects public IP addresses and public hostnames.

## Run the local agent

Python 3.10 or newer is required. From the repository directory:

```bash
python -m venv .venv
# Linux/macOS:
source .venv/bin/activate
# Windows PowerShell:
# .venv\Scripts\Activate.ps1
python -m pip install -r requirements.txt
./run-agent.sh
```

On Windows, start it with `python -m lass.agent` if the shell does not run the `.sh` script. The agent binds only to `127.0.0.1:8765`; it is not exposed as a network server. On startup it prints a random pairing token in the terminal. Keep that terminal open while scanning.

You can also run the agent directly with `python -m lass.agent`. Scan history is stored in SQLite at `~/.local/share/lass/scans.sqlite3` (or `%USERPROFILE%\\.local\\share\\lass\\scans.sqlite3` on Windows). Set `LASS_DB_PATH` to choose another database file. Set `LASS_ALLOWED_ORIGIN` if your Vercel site has a different exact origin; the default is `https://l-a-s-s-local-api-security-scanner.vercel.app`.

## Open the web interface

Deploy the repository to Vercel using the default static deployment configuration. Vercel serves only the files in `static/`; it has no scan function and cannot scan targets. Open your deployed Vercel URL, confirm the browser's local-network permission if prompted, paste the pairing token printed by the running agent, and check that the status reads **Agent connected**.

For local development, serve the static files from an allowed localhost origin:

```bash
python -m http.server 8000 --directory static
```

Then open `http://localhost:8000`. Start the agent separately. The UI also includes a **Check agent** control and setup steps when the agent is unavailable.

## Pairing and scan behavior

Paste the terminal token into the UI once per browser tab/session. It is held in `sessionStorage` (or memory when storage is unavailable) and sent in the `X-LASS-Token` header. The token changes every time the agent restarts. Scan requests also require the authorization confirmation checkbox; the agent enforces it independently of the UI.

Only HTTP and HTTPS URLs with `localhost`, `127.0.0.1`, `::1`, or addresses in `10.0.0.0/8`, `172.16.0.0/12`, and `192.168.0.0/16` are accepted. Hostnames are resolved and every returned address must be in the allowlist. Public targets are rejected before HTTPX is called. The agent makes one GET request, does not follow redirects, uses an eight-second timeout, and allows at most 10 scans per minute per client. Successful and failed connection results are saved to SQLite and returned in Recent scans.

The report shows HTTP status, response time, and a 100-point baseline score. Findings cover common missing security headers, wildcard CORS, server errors, and technology disclosure. High, medium, and low findings deduct 20, 10, and 5 points respectively. L.A.S.S. is a lightweight developer baseline, not a full OWASP scanner or a substitute for an authorized security assessment.

## Browser permissions and troubleshooting

- **Chrome Local Network Access:** Current Chrome is rolling out a Local Network Access permission (Chrome 142). When the Vercel page requests the local agent, choose **Allow** in the browser prompt. If it was denied, open the Vercel site's controls or Site settings, set **Local network access** to **Allow**, then reload. The permission is available to secure contexts such as the HTTPS Vercel site. See [Chrome's Local Network Access announcement](https://developer.chrome.com/blog/local-network-access/).
- **Agent not running:** Start `python -m lass.agent`, leave its terminal open, then click **Check agent**. Confirm that port `8765` is available and the agent prints its pairing token.
- **Pairing or 401 error:** Paste the token from the current agent process. Restarting the process creates a new token. The UI sends it only to `127.0.0.1` and keeps it for the current browser session.
- **CORS / origin denied:** Use the deployed Vercel origin configured in `LASS_ALLOWED_ORIGIN`, or serve the UI from `http://localhost` for development. Other origins are deliberately rejected. Restart the agent after changing `LASS_ALLOWED_ORIGIN`.
- **Safari or mixed-content error:** Some browser/OS combinations may block an HTTPS page from reaching an HTTP loopback service or may handle local-network permission differently. Try the localhost development UI (`http://localhost:8000`) in Safari, or use a current Chrome/Edge release and allow its Local Network Access prompt. Do not expose the agent on a LAN interface to work around browser restrictions.
- **Target rejected:** Check that the URL uses `http://` or `https://`, has no credentials, and is a loopback/private IPv4 target. Public IPs and hostnames resolving to any public IP are intentionally blocked.

## Tests

```bash
python -m pytest
```

The tests cover the target gate, hostname resolution, agent-origin and pairing controls, storage, and scoring.
