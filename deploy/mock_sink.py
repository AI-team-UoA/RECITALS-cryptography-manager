"""
A stand-in for a downstream audit consumer.

Used by docker-compose to give the Cryptography Manager somewhere to forward
audit records during local development, so the forwarding path is exercised
rather than merely configured. Every received record is echoed to stdout,
which makes `docker compose logs` a live view of the audit trail.

This is a development fixture. It authenticates nothing, stores nothing
durably, and must never stand in for a real ledger or compliance service.
"""

from __future__ import annotations

import json
import os
import sys
from http.server import BaseHTTPRequestHandler, HTTPServer

SERVICE = os.environ.get("MOCK_SERVICE_NAME", "sink")
PORT = int(os.environ.get("MOCK_PORT", "9000"))


class Handler(BaseHTTPRequestHandler):
    """Accept any POST, log it, and acknowledge."""

    received: list[dict] = []

    def log_message(self, *args: object) -> None:
        """Suppress the default access log; records are logged instead."""

    def _respond(self, code: int, body: dict) -> None:
        payload = json.dumps(body).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)

    def do_GET(self) -> None:  # noqa: N802
        if self.path == "/health":
            self._respond(200, {"status": "ok", "service": SERVICE})
        elif self.path == "/received":
            self._respond(200, {"count": len(Handler.received),
                                "records": Handler.received[-50:]})
        else:
            self._respond(404, {"error": "not found"})

    def do_POST(self) -> None:  # noqa: N802
        length = int(self.headers.get("Content-Length", 0))
        raw = self.rfile.read(length) if length else b"{}"
        try:
            record = json.loads(raw)
        except json.JSONDecodeError:
            self._respond(400, {"error": "invalid JSON"})
            return

        Handler.received.append(record)
        print(
            f"[{SERVICE}] {self.path} <- "
            f"audit_id={record.get('audit_id')} "
            f"status={record.get('status')} "
            f"operation={record.get('operation')} "
            f"user={record.get('user_id')}",
            flush=True,
        )
        self._respond(202, {"accepted": True, "service": SERVICE})


if __name__ == "__main__":
    print(f"[{SERVICE}] listening on :{PORT}", flush=True)
    try:
        HTTPServer(("0.0.0.0", PORT), Handler).serve_forever()
    except KeyboardInterrupt:
        sys.exit(0)
