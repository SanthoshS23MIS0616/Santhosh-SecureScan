# Frontend And Backend Flow

1. User enters a target in the Santhosh SecureScan dashboard.
2. The frontend sends JSON to `POST /api/scan`.
3. The backend validates the target and scan profile.
4. The scanner checks ports, banners, web headers, TLS, and software hints.
5. The backend returns a structured vulnerability result.
6. The frontend renders metrics, findings, open ports, and the final report.

## API Request

```json
{
  "target": "http://127.0.0.1:8000",
  "profile": "quick",
  "customPorts": ""
}
```

## API Output

```json
{
  "ok": true,
  "result": {
    "risk_score": 80,
    "open_ports": [],
    "findings": [],
    "report_markdown": "..."
  }
}
```
