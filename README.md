# Santhosh SecureScan - Vulnerability Scanner Mini Project

Santhosh SecureScan is an intermediate-level full-stack mini project for vulnerability assessment practice. It scans a target web application or host, detects open ports, checks common weak web configurations, highlights exposed services, flags outdated-looking software banners, and produces a clean report.

## Language Combination

- Frontend: HTML, CSS, JavaScript
- Backend: Python standard library
- Communication: Frontend calls backend with JSON through `/api/scan`
- Report: Backend generates a Markdown vulnerability report, frontend can download Markdown or JSON

This combination keeps the project professional and easy to run without installing heavy packages.

## Project Structure

```text
2nd proj/
  backend/
    scanner.py          # Core port, HTTP, TLS, banner, and finding logic
    server.py           # API server and static frontend hosting
    test_scanner.py     # Small backend tests
  frontend/
    index.html          # Scanner interface
    styles.css          # Professional animated UI
    app.js              # API calls, rendering, report download
  reports/              # Optional place for saved reports
  .gitignore
  README.md
  start.ps1
```

## How Frontend And Backend Interconnect

1. `backend/server.py` serves the frontend from the `frontend` folder.
2. The user enters a target in the browser.
3. `frontend/app.js` sends a POST request to `/api/scan`.
4. `backend/server.py` receives the JSON and calls `backend/scanner.py`.
5. `scanner.py` returns open ports, HTTP security checks, software hints, and findings.
6. The frontend renders the dashboard and downloads the report when requested.

## Run

```powershell
cd "C:\Users\santhosh\OneDrive\Desktop\intern\fullstack\2nd proj"
.\start.ps1
```

Then open:

```text
http://127.0.0.1:8000
```

You can also run directly:

```powershell
python .\backend\server.py
```

## Test

```powershell
python -m unittest .\backend\test_scanner.py
```

## Key Features

- Scan open ports with quick, web, and extended profiles
- Detect exposed risky services such as FTP, Telnet, databases, and remote access ports
- Grab simple service banners where available
- Inspect HTTP headers and identify missing security headers
- Check TLS certificate expiry and negotiated TLS version for HTTPS ports
- Identify outdated-looking software versions from banners and HTTP headers
- Generate a polished vulnerability report with risk score and recommendations

## Ethical Use

Use this only on systems you own or have clear permission to test. The scanner is intentionally scoped for learning and basic assessment, not aggressive exploitation.

## GitHub Commit And Push Commands

Use these commands from the project folder when you want to recreate the manual Git flow:

```powershell
git init -b main
git remote add origin https://github.com/SanthoshS23MIS0616/Santhosh-SecureScan.git
git add .gitignore start.ps1 reports/.gitkeep
git commit -m "Initialize project workspace"
git add backend/scanner.py
git commit -m "Add vulnerability scanning engine"
git add backend/server.py
git commit -m "Add backend API server"
git add frontend/index.html
git commit -m "Add scanner dashboard markup"
git add frontend/styles.css
git commit -m "Add professional animated interface"
git add frontend/app.js
git commit -m "Connect frontend scan workflow"
git add backend/test_scanner.py
git commit -m "Add scanner unit tests"
git add docs README.md
git commit -m "Add project documentation"
git push -u origin main
```

