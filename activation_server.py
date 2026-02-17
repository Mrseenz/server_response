#!/usr/bin/env python3
"""Minimal iDevice activation protocol emulator based on captured traffic.

This server can replay captured `/deviceservices/drmHandshake` payloads and can
mint synthetic activation records for `/deviceservices/deviceActivation` so the
activation flow can be studied with regenerated artifacts.

Important: minted records are locally signed for lab analysis and are not Apple-
trusted activation tickets.
"""

from __future__ import annotations

import argparse
import base64
import datetime as dt
import json
import os
import plistlib
import re
import subprocess
import tempfile
import textwrap
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parent


def _load_handshake_plist() -> bytes:
    raw = (ROOT / "4 handshake" / "handshake_response.json").read_text()
    decoder = json.JSONDecoder()
    obj, _ = decoder.raw_decode(raw)
    return bytes(obj[str(i)] for i in range(len(obj)))


def _load_failure_activation_html() -> str:
    return (ROOT / "5 deviceActivation" / "deviceActivation_response.txt").read_text()


def _extract_activation_info_xml(raw_body: bytes) -> dict[str, Any] | None:
    text = raw_body.decode("utf-8", errors="ignore")
    if 'name="activation-info"' not in text:
        return None

    # Capture <key>ActivationInfoXML</key><data>....</data> from multipart body.
    m = re.search(r"<key>ActivationInfoXML</key>\s*<data>\s*(.*?)\s*</data>", text, re.S)
    if not m:
        return None

    try:
        payload = base64.b64decode("".join(m.group(1).split()))
        return plistlib.loads(payload)
    except Exception:
        return None


def _run(cmd: list[str], cwd: Path | None = None) -> None:
    result = subprocess.run(cmd, cwd=cwd, capture_output=True, text=True, check=False)
    if result.returncode != 0:
        raise RuntimeError(f"Command failed: {' '.join(cmd)}\n{result.stderr}")


class LocalActivationMint:
    """Mint synthetic activation records using a local lab CA."""

    def __init__(self, root: Path) -> None:
        self.root = root
        self.ca_dir = root / "artifacts" / "local_ca"
        self.ca_dir.mkdir(parents=True, exist_ok=True)
        self.ca_key = self.ca_dir / "local_activation_ca.key"
        self.ca_cert = self.ca_dir / "local_activation_ca.pem"
        self._ensure_ca()

    def _ensure_ca(self) -> None:
        if self.ca_key.exists() and self.ca_cert.exists():
            return

        _run(["openssl", "genrsa", "-out", str(self.ca_key), "2048"])
        _run(
            [
                "openssl",
                "req",
                "-x509",
                "-new",
                "-key",
                str(self.ca_key),
                "-sha256",
                "-days",
                "3650",
                "-subj",
                "/C=US/O=Activation Lab/CN=Local Activation Root CA",
                "-out",
                str(self.ca_cert),
            ]
        )

    def _issue_cert(self, cn: str, prefix: str) -> bytes:
        with tempfile.TemporaryDirectory() as td:
            tmp = Path(td)
            key = tmp / f"{prefix}.key"
            csr = tmp / f"{prefix}.csr"
            crt = tmp / f"{prefix}.crt"

            _run(["openssl", "genrsa", "-out", str(key), "2048"])
            _run(
                [
                    "openssl",
                    "req",
                    "-new",
                    "-key",
                    str(key),
                    "-subj",
                    f"/C=US/O=Activation Lab/OU=Minted/CN={cn}",
                    "-out",
                    str(csr),
                ]
            )
            _run(
                [
                    "openssl",
                    "x509",
                    "-req",
                    "-in",
                    str(csr),
                    "-CA",
                    str(self.ca_cert),
                    "-CAkey",
                    str(self.ca_key),
                    "-CAcreateserial",
                    "-days",
                    "825",
                    "-sha256",
                    "-out",
                    str(crt),
                ]
            )
            return crt.read_bytes()

    def _sign_blob(self, blob: bytes) -> bytes:
        with tempfile.TemporaryDirectory() as td:
            tmp = Path(td)
            source = tmp / "blob.bin"
            sig = tmp / "blob.sig"
            source.write_bytes(blob)
            _run(["openssl", "dgst", "-sha256", "-sign", str(self.ca_key), "-out", str(sig), str(source)])
            return sig.read_bytes()

    def mint_activation_record(self, activation_info: dict[str, Any]) -> dict[str, Any]:
        device_id = activation_info.get("DeviceID", {})
        device_info = activation_info.get("DeviceInfo", {})
        activation_request = activation_info.get("ActivationRequestInfo", {})

        serial = str(device_id.get("SerialNumber", "UNKNOWN-SERIAL"))
        udid = str(device_id.get("UniqueDeviceID", "UNKNOWN-UDID"))
        product = str(device_info.get("ProductType", "UnknownProduct"))
        randomness = str(activation_request.get("ActivationRandomness", "UNKNOWN-RAND"))

        account_token_obj = {
            "SerialNumber": serial,
            "UniqueDeviceID": udid,
            "ProductType": product,
            "ActivationRandomness": randomness,
            "Issuer": "Local Activation Lab",
            "IssuedAtUTC": dt.datetime.now(tz=dt.timezone.utc).isoformat(),
            "PhoneNumberNotificationURL": "https://albert.apple.com/deviceservices/phoneHome",
            "ActivityURL": "https://albert.apple.com/deviceservices/activity",
        }
        account_token = json.dumps(account_token_obj, indent=2, sort_keys=True).encode()
        account_token_signature = self._sign_blob(account_token)

        account_token_cert = self._issue_cert("AccountTokenSigning", "account_token")
        device_cert = self._issue_cert(serial, "device")
        unique_device_cert = self._issue_cert(udid, "unique_device")

        fairplay_payload = base64.b64encode(os.urandom(96) + account_token_signature)
        fairplay_container = textwrap.fill(fairplay_payload.decode(), width=64)
        fairplay_data = (
            "-----BEGIN CONTAINER-----\n"
            f"{fairplay_container}\n"
            "-----END CONTAINER-----\n"
        ).encode()

        regulatory = json.dumps(
            {"elabel": {"bis": {"regulatory": f"LAB-{serial[-6:]}"}}},
            separators=(",", ":"),
        ).encode()

        return {
            "unbrick": True,
            "AccountTokenCertificate": account_token_cert,
            "DeviceCertificate": device_cert,
            "RegulatoryInfo": regulatory,
            "FairPlayKeyData": fairplay_data,
            "AccountToken": account_token,
            "AccountTokenSignature": account_token_signature,
            "UniqueDeviceCertificate": unique_device_cert,
        }

    def render_activation_html(self, activation_info: dict[str, Any]) -> str:
        payload = {"ActivationRecord": self.mint_activation_record(activation_info)}
        plist_xml = plistlib.dumps(payload, fmt=plistlib.FMT_XML, sort_keys=False).decode()

        return f"""<!DOCTYPE html>
<html>
  <head>
    <meta http-equiv=\"Content-Type\" content=\"text/html; charset=utf-8\" />
    <title>iPhone Activation</title>
    <script id=\"protocol\" type=\"text/x-apple-plist\">{plist_xml}</script>
    <script>
      var protocolElement = document.getElementById("protocol");
      var protocolContent = protocolElement.innerText;
      if (typeof iTunes !== "undefined" && iTunes.addProtocol) {{
        iTunes.addProtocol(protocolContent);
      }}
    </script>
  </head>
  <body></body>
</html>
"""


HANDSHAKE_RESPONSE = _load_handshake_plist()
ACTIVATION_FAILURE_HTML = _load_failure_activation_html()


class ActivationHandler(BaseHTTPRequestHandler):
    server_version = "Apple"
    sys_version = ""

    mint = LocalActivationMint(ROOT)

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
            activation_info = _extract_activation_info_xml(body)
            if activation_info is None:
                self._send(200, "text/html", ACTIVATION_FAILURE_HTML.encode())
                return

            html = self.mint.render_activation_html(activation_info)
            self._send(200, "text/html", html.encode())
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
