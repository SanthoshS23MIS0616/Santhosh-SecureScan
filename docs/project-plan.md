# Project Plan

## Objective
Build Santhosh SecureScan as a professional intermediate-level vulnerability scanner mini project.

## Frontend Plan
- Single-page dashboard with target input, scan profiles, and custom port support.
- Animated glass-style security console with responsive layout.
- Metrics for risk score, open ports, findings, and scan duration.
- Report preview with Markdown and JSON downloads.

## Backend Plan
- Python HTTP API using standard library only.
- `/api/health` for service status.
- `/api/scan` for scanning target, ports, headers, TLS, and version hints.
- Structured JSON response for frontend rendering.

## Scanner Plan
- Normalize hostnames, URLs, and requested ports.
- Resolve DNS and scan selected TCP ports with short timeouts.
- Grab service banners safely.
- Inspect HTTP headers and missing security controls.
- Generate risk score and Markdown report.
