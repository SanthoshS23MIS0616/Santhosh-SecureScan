from __future__ import annotations

import json
import mimetypes
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import unquote

from scanner import scan_target


ROOT = Path(__file__).resolve().parents[1]
FRONTEND = ROOT / "frontend"
HOST = "127.0.0.1"
PORT = 8000


class AegisHandler(BaseHTTPRequestHandler):
    server_version = "SanthoshSecureScan/1.0"

    def log_message(self, fmt: str, *args: object) -> None:
        print(f"[SanthoshSecureScan] {self.address_string()} - {fmt % args}")

    def _send_json(self, payload: dict, status: int = 200) -> None:
        body = json.dumps(payload, indent=2).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
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

    def do_GET(self) -> None:
        if self.path == "/api/health":
            self._send_json({"ok": True, "service": "Santhosh SecureScan API"})
            return
        self._serve_static()

    def do_POST(self) -> None:
        if self.path == "/api/scan":
            self._handle_scan()
            return
        if self.path == "/api/report":
            self._handle_report()
            return
        self._send_json({"error": "Route not found."}, status=404)

    def _handle_scan(self) -> None:
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
        except Exception as exc:  # Keeps the frontend reportable during student testing.
            self._send_json({"ok": False, "error": f"Scan failed: {exc}"}, status=500)

    def _handle_report(self) -> None:
        try:
            payload = self._read_json()
            report = payload.get("report_markdown") or payload.get("report") or ""
            if not report:
                self._send_json({"ok": False, "error": "Report content is required."}, status=400)
                return
            self._send_json({"ok": True, "report": report})
        except json.JSONDecodeError:
            self._send_json({"ok": False, "error": "Invalid JSON."}, status=400)

    def _serve_static(self) -> None:
        requested = unquote(self.path.split("?", 1)[0])
        if requested in {"/", ""}:
            file_path = FRONTEND / "index.html"
        else:
            clean = requested.lstrip("/")
            file_path = FRONTEND / clean

        try:
            resolved = file_path.resolve()
            if not str(resolved).startswith(str(FRONTEND.resolve())) or not resolved.exists():
                self._send_json({"error": "File not found."}, status=404)
                return
            content = resolved.read_bytes()
            content_type = mimetypes.guess_type(str(resolved))[0] or "application/octet-stream"
            self.send_response(200)
            self.send_header("Content-Type", content_type)
            self.send_header("Content-Length", str(len(content)))
            self.end_headers()
            self.wfile.write(content)
        except OSError as exc:
            self._send_json({"error": str(exc)}, status=500)


def run() -> None:
    print(f"Santhosh SecureScan running at http://{HOST}:{PORT}")
    print("Press Ctrl+C to stop.")
    with ThreadingHTTPServer((HOST, PORT), AegisHandler) as httpd:
        httpd.serve_forever()


if __name__ == "__main__":
    run()



