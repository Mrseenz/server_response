#!/usr/bin/env python3
"""Captured iDevice activation replay server (analysis/testing only).

This server replays captured `/deviceservices/drmHandshake` and
`/deviceservices/deviceActivation` payloads from local capture directories.
It cannot generate Apple-signed activation tickets.
"""

from __future__ import annotations

import argparse
import base64
import json
import plistlib
import re
from dataclasses import dataclass
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path

ROOT = Path(__file__).resolve().parent


@dataclass(frozen=True)
class ActivationProfile:
    name: str
    product_type: str | None
    handshake_response: bytes | None
    activation_html: str | None


def _load_handshake_plist(path: Path) -> bytes:
    raw = path.read_text()
    decoder = json.JSONDecoder()
    obj, _ = decoder.raw_decode(raw)
    return bytes(obj[str(i)] for i in range(len(obj)))


def _extract_product_type(req_path: Path) -> str | None:
    text = req_path.read_text()
    m = re.search(r"<key>ActivationInfoXML</key>\s*<data>\s*(.*?)\s*</data>", text, re.S)
    if not m:
        return None
    payload = plistlib.loads(base64.b64decode("".join(m.group(1).split())))
    return payload.get("DeviceInfo", {}).get("ProductType")


def _discover_profiles() -> list[ActivationProfile]:
    profiles: list[ActivationProfile] = []
    for d in sorted(ROOT.iterdir()):
        if not d.is_dir() or not (d / "url.txt").exists():
            continue
        hs = _load_handshake_plist(d / "handshake_response.json") if (d / "handshake_response.json").exists() else None
        act_html = (d / "deviceActivation_response.txt").read_text() if (d / "deviceActivation_response.txt").exists() else None
        product = _extract_product_type(d / "deviceActivation_request.txt") if (d / "deviceActivation_request.txt").exists() else None
        if hs is None and act_html is None:
            continue
        profiles.append(ActivationProfile(name=d.name, product_type=product, handshake_response=hs, activation_html=act_html))
    return profiles


PROFILES = _discover_profiles()
DEFAULT_HANDSHAKE = next((p.handshake_response for p in PROFILES if p.handshake_response is not None), b"")
DEFAULT_ACTIVATION = next((p.activation_html for p in PROFILES if p.activation_html is not None), "")


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

    def _select_activation_html(self, body_text: str) -> str:
        product_match = re.search(r"<key>ProductType</key>\s*<string>([^<]+)</string>", body_text)
        product = product_match.group(1) if product_match else None
        if product:
            match = next((p for p in PROFILES if p.product_type == product and p.activation_html), None)
            if match:
                return match.activation_html or DEFAULT_ACTIVATION
        return DEFAULT_ACTIVATION

    def do_POST(self) -> None:  # noqa: N802
        length = int(self.headers.get("Content-Length", "0"))
        body = self.rfile.read(length)
        text = body.decode("utf-8", errors="ignore")

        if self.path.endswith("/deviceservices/drmHandshake"):
            self._send(200, "application/xml", DEFAULT_HANDSHAKE)
            return

        if self.path.endswith("/deviceservices/deviceActivation"):
            if re.search(r'name="activation-info"', text) and "ActivationInfoXML" in text:
                html = self._select_activation_html(text)
                self._send(200, "text/html", html.encode())
            else:
                self._send(400, "text/plain", b"Malformed activation-info payload")
            return

        self._send(404, "text/plain", b"Not Found")


def main() -> None:
    parser = argparse.ArgumentParser(description="Run captured iDevice activation replay server")
    parser.add_argument("--host", default="0.0.0.0")
    parser.add_argument("--port", default=8080, type=int)
    args = parser.parse_args()

    httpd = HTTPServer((args.host, args.port), ActivationHandler)
    print(f"Listening on http://{args.host}:{args.port} (profiles: {len(PROFILES)})")
    httpd.serve_forever()


if __name__ == "__main__":
    main()
