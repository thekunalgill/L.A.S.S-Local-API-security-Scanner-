# L.A.S.S. — API Security Scanner

L.A.S.S. provides a web interface and desktop app for checking API response health and baseline security headers. The web app is stateless and needs no account, database, or Vercel environment variables. Scan history is stored in the user's browser. Desktop scans can target localhost and authorized private LAN hosts; hosted scans are restricted to public IP addresses.

## Deploy from GitHub to Vercel

1. Push this repository to GitHub and import it in Vercel. The root `index.py` entrypoint serves the FastAPI app, and `vercel.json` includes the static frontend assets.
2. Deploy with Vercel's default settings. No database, credentials, or environment variables are required.

Hosted scans accept public IP addresses and hostnames that resolve only to public IPs. Private, loopback, and link-local destinations are blocked, and redirects are not followed. The authorization checkbox is a reminder, not access control; only scan systems you own or have permission to test. History stays in the current browser and is not shared across browsers or devices. Vercel serverless functions are intended for these short, single-request checks, not long-running scans.

## Build or run the desktop app

Python 3.10 or newer is required for development.

```bash
python -m venv .venv
# Linux:
source .venv/bin/activate
# Windows PowerShell:
# .venv\Scripts\Activate.ps1
python -m pip install -r requirements-desktop.txt
python desktop.py
```

Linux requires GTK 3, WebKitGTK 4.1, and the matching PyGObject (`python3-gi`) runtime. For development builds, install their development packages. On Ubuntu 24.04:

```bash
sudo apt install libgtk-3-dev libwebkit2gtk-4.1-dev python3-gi
```

On Arch Linux and derivatives, install `gtk3`, `webkit2gtk-4.1`, and `python-gobject` with pacman. Windows uses Microsoft Edge WebView2; install its Evergreen Runtime if it is not already present.

## Build desktop binaries

Build on the operating system for which you want a binary; Windows and Linux builds are not cross-compiled.

```bash
python -m pip install -r requirements-desktop.txt
python -m PyInstaller --clean --noconfirm lass.spec
```

The executable will be in `dist/`. Releases tagged `v*` are built by GitHub Actions on native Windows and Linux runners and attached to the GitHub Release. Linux users need GTK 3 and WebKitGTK 4.1 installed on their system; Windows users need the Edge WebView2 Runtime.

## Use the desktop app

Enter a URL such as `http://localhost:8000/health`, `http://127.0.0.1:8000/`, or a private LAN IP address, then confirm that you are authorized to test it. Public IPs, domain names, redirects, and URL credentials are blocked. Local-network scans are only for machines you own or have explicit permission to assess. The scanner makes one GET request, with an eight-second timeout, and does not follow redirects. Hosted scans allow public hosts only and pin each connection to the public address validated by DNS.

The tool checks response time, HTTP status, common security headers, wildcard CORS and technology disclosure, then deducts 20/10/5 points per high/medium/low finding from a score of 100. Scan history is stored locally in the browser's storage.

This is a lightweight developer baseline, not a full OWASP scanner or a substitute for security testing.

## Development tests

```bash
python -m unittest discover -s tests -v
```
