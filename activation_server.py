#!/usr/bin/env python3
"""Minimal iDevice activation protocol emulator based on captured traffic.

This server replays captured `/deviceservices/drmHandshake` and
`/deviceservices/deviceActivation` payloads.

It is useful for protocol experimentation only. It does NOT generate real
Apple-signed activation tickets.
"""

from __future__ import annotations

import argparse
import json
import re
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path

ROOT = Path(__file__).resolve().parent


def _load_handshake_plist() -> bytes:
    raw = (ROOT / "4 handshake" / "handshake_response.json").read_text()
    decoder = json.JSONDecoder()
    obj, _ = decoder.raw_decode(raw)
    return bytes(obj[str(i)] for i in range(len(obj)))


def _load_success_activation_html() -> str:
    return (ROOT / "2 deviceActivation" / "deviceActivation_response.txt").read_text()


def _load_failure_activation_html() -> str:
    return (ROOT / "5 deviceActivation" / "deviceActivation_response.txt").read_text()


HANDSHAKE_RESPONSE = _load_handshake_plist()
ACTIVATION_SUCCESS_HTML = _load_success_activation_html()
ACTIVATION_FAILURE_HTML = _load_failure_activation_html()


class ActivationHandler(BaseHTTPRequestHandler):
    server_version = "Apple"
    sys_version = ""

    def _send(self, status: int, content_type: str, body: bytes) -> None:
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Cache-Control", "no-cache, no-store, max-age=0, must-revalidate")
        self.send_header("Connection", "close")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_POST(self) -> None:  # noqa: N802
        length = int(self.headers.get("Content-Length", "0"))
        body = self.rfile.read(length)

        if self.path.endswith("/deviceservices/drmHandshake"):
            self._send(200, "application/xml", HANDSHAKE_RESPONSE)
            return

        if self.path.endswith("/deviceservices/deviceActivation"):
            # Very lightweight validation: if request contains activation-info
            # and ActivationInfoXML, return captured success, else return the
            # ack/show-settings response.
            as_text = body.decode("utf-8", errors="ignore")
            if re.search(r'name="activation-info"', as_text) and "ActivationInfoXML" in as_text:
                self._send(200, "text/html", ACTIVATION_SUCCESS_HTML.encode())
            else:
                self._send(200, "text/html", ACTIVATION_FAILURE_HTML.encode())
            return

        self._send(404, "text/plain", b"Not Found")


def main() -> None:
    parser = argparse.ArgumentParser(description="Run captured iDevice activation emulator")
    parser.add_argument("--host", default="0.0.0.0")
    parser.add_argument("--port", default=8080, type=int)
    args = parser.parse_args()

    httpd = HTTPServer((args.host, args.port), ActivationHandler)
    print(f"Listening on http://{args.host}:{args.port}")
    httpd.serve_forever()


if __name__ == "__main__":
    main()
