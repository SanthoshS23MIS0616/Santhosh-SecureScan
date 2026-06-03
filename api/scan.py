from __future__ import annotations

import json
from http.server import BaseHTTPRequestHandler

from backend.scanner import scan_target


class handler(BaseHTTPRequestHandler):
    def _send_json(self, payload: dict, status: int = 200) -> None:
        body = json.dumps(payload, indent=2).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Access-Control-Allow-Methods", "POST, OPTIONS")
        self.send_header("Access-Control-Allow-Headers", "Content-Type")
        self.end_headers()
        self.wfile.write(body)

    def _read_json(self) -> dict:
        length = int(self.headers.get("Content-Length", "0"))
        if length <= 0:
            return {}
        raw = self.rfile.read(length).decode("utf-8")
        return json.loads(raw or "{}")

    def do_OPTIONS(self) -> None:
        self._send_json({"ok": True})

    def do_POST(self) -> None:
        try:
            payload = self._read_json()
            result = scan_target(
                raw_target=payload.get("target", ""),
                profile=payload.get("profile", "quick"),
                custom_ports=payload.get("customPorts", ""),
            )
            self._send_json({"ok": True, "result": result})
        except ValueError as exc:
            self._send_json({"ok": False, "error": str(exc)}, status=400)
        except json.JSONDecodeError:
            self._send_json({"ok": False, "error": "Invalid JSON."}, status=400)
        except Exception as exc:
            self._send_json({"ok": False, "error": f"Scan failed: {exc}"}, status=500)
