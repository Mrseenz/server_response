#!/usr/bin/env python3
"""iDevice activation protocol emulator based on captured traffic.

The server replays captured `/deviceservices/drmHandshake` responses and mints
new `/deviceservices/deviceActivation` records while mimicking certificate
algorithms/profile extracted from the repository's captured Apple response.
"""

from __future__ import annotations

import argparse
import base64
import datetime as dt
import hashlib
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


def _load_captured_activation_record() -> dict[str, Any]:
    html = (ROOT / "2 deviceActivation" / "deviceActivation_response.txt").read_text()
    m = re.search(r'<script id="protocol" type="text/x-apple-plist">\s*(.*?)\s*</script>', html, re.S)
    if not m:
        raise ValueError("Captured activation plist not found")
    payload = plistlib.loads(m.group(1).encode())
    return payload["ActivationRecord"]


def _extract_activation_info_xml(raw_body: bytes) -> dict[str, Any] | None:
    text = raw_body.decode("utf-8", errors="ignore")
    if 'name="activation-info"' not in text:
        return None

    m = re.search(r"<key>ActivationInfoXML</key>\s*<data>\s*(.*?)\s*</data>", text, re.S)
    if not m:
        return None

    try:
        payload = base64.b64decode("".join(m.group(1).split()))
        return plistlib.loads(payload)
    except Exception:
        return None


def _run(cmd: list[str]) -> subprocess.CompletedProcess[str]:
    return subprocess.run(cmd, capture_output=True, text=True, check=False)


def _run_ok(cmd: list[str]) -> subprocess.CompletedProcess[str]:
    result = _run(cmd)
    if result.returncode != 0:
        raise RuntimeError(f"Command failed: {' '.join(cmd)}\n{result.stderr}")
    return result


class CapturedCryptoProfile:
    """Metadata extracted from captured response certificates/signatures."""

    def __init__(self, activation_record: dict[str, Any]) -> None:
        self.activation_record = activation_record
        self.profile = self._extract_profile()

    def _cert_info(self, cert_bytes: bytes) -> dict[str, str]:
        with tempfile.NamedTemporaryFile(delete=False) as tmp:
            tmp.write(cert_bytes)
            cert_path = tmp.name
        try:
            text = _run_ok(["openssl", "x509", "-in", cert_path, "-noout", "-text"]).stdout
            pubkey = _run_ok(["openssl", "x509", "-in", cert_path, "-noout", "-pubkey"]).stdout
        finally:
            os.unlink(cert_path)

        info: dict[str, str] = {"pubkey_sha256": hashlib.sha256(pubkey.encode()).hexdigest()}
        for line in text.splitlines():
            stripped = line.strip()
            if stripped.startswith("Signature Algorithm:") and "signature_algorithm" not in info:
                info["signature_algorithm"] = stripped.split(":", 1)[1].strip()
            if stripped.startswith("Public Key Algorithm:"):
                info["public_key_algorithm"] = stripped.split(":", 1)[1].strip()
            if stripped.startswith("Public-Key:"):
                info["public_key_size"] = stripped.split(":", 1)[1].strip().strip("()")
        return info

    def _extract_profile(self) -> dict[str, Any]:
        account_sig = self.activation_record.get("AccountTokenSignature", b"")
        return {
            "AccountTokenCertificate": self._cert_info(self.activation_record["AccountTokenCertificate"]),
            "DeviceCertificate": self._cert_info(self.activation_record["DeviceCertificate"]),
            "UniqueDeviceCertificate": self._cert_info(self.activation_record["UniqueDeviceCertificate"]),
            "captured_account_token_signature_len": len(account_sig),
            "captured_account_token_signature_sha256": hashlib.sha256(account_sig).hexdigest() if account_sig else None,
            "captured_fairplay_prefix": self.activation_record.get("FairPlayKeyData", b"")[:64].decode("utf-8", errors="ignore"),
        }


class MimicActivationMint:
    """Mint synthetic activation records while mimicking captured crypto profile."""

    def __init__(self, root: Path, captured_record: dict[str, Any], profile: CapturedCryptoProfile) -> None:
        self.root = root
        self.captured_record = captured_record
        self.profile = profile.profile
        self.ca_dir = root / "artifacts" / "mimic_ca"
        self.ca_dir.mkdir(parents=True, exist_ok=True)

        self.rsa_ca_key = self.ca_dir / "rsa_ca.key"
        self.rsa_ca_cert = self.ca_dir / "rsa_ca.pem"
        self.ec_ca_key = self.ca_dir / "ec_ca.key"
        self.ec_ca_cert = self.ca_dir / "ec_ca.pem"
        self._ensure_cas()

    def _ensure_cas(self) -> None:
        if not (self.rsa_ca_key.exists() and self.rsa_ca_cert.exists()):
            _run_ok(["openssl", "genrsa", "-out", str(self.rsa_ca_key), "1024"])
            _run_ok(
                [
                    "openssl",
                    "req",
                    "-x509",
                    "-new",
                    "-key",
                    str(self.rsa_ca_key),
                    "-sha1",
                    "-days",
                    "3650",
                    "-subj",
                    "/C=US/O=Apple Inc./OU=Apple iPhone/CN=Apple iPhone Device CA (Mimic)",
                    "-out",
                    str(self.rsa_ca_cert),
                ]
            )

        if not (self.ec_ca_key.exists() and self.ec_ca_cert.exists()):
            _run_ok(["openssl", "ecparam", "-genkey", "-name", "prime256v1", "-out", str(self.ec_ca_key)])
            _run_ok(
                [
                    "openssl",
                    "req",
                    "-x509",
                    "-new",
                    "-key",
                    str(self.ec_ca_key),
                    "-sha256",
                    "-days",
                    "3650",
                    "-subj",
                    "/ST=California/O=Apple Inc./CN=SEP Root CA (Mimic)",
                    "-out",
                    str(self.ec_ca_cert),
                ]
            )

    def _issue_rsa1024_cert(self, cn: str, prefix: str) -> bytes:
        with tempfile.TemporaryDirectory() as td:
            tmp = Path(td)
            key = tmp / f"{prefix}.key"
            csr = tmp / f"{prefix}.csr"
            crt = tmp / f"{prefix}.crt"
            _run_ok(["openssl", "genrsa", "-out", str(key), "1024"])
            _run_ok(["openssl", "req", "-new", "-key", str(key), "-subj", f"/C=US/ST=CA/L=Cupertino/O=Apple Inc./OU=iPhone/CN={cn}", "-out", str(csr)])
            _run_ok(["openssl", "x509", "-req", "-in", str(csr), "-CA", str(self.rsa_ca_cert), "-CAkey", str(self.rsa_ca_key), "-CAcreateserial", "-days", "825", "-sha1", "-out", str(crt)])
            return crt.read_bytes()

    def _issue_ecp256_cert(self, cn: str, prefix: str) -> bytes:
        with tempfile.TemporaryDirectory() as td:
            tmp = Path(td)
            key = tmp / f"{prefix}.key"
            csr = tmp / f"{prefix}.csr"
            crt = tmp / f"{prefix}.crt"
            _run_ok(["openssl", "ecparam", "-genkey", "-name", "prime256v1", "-out", str(key)])
            _run_ok(["openssl", "req", "-new", "-key", str(key), "-subj", f"/ST=California/O=Apple Inc./CN={cn}", "-out", str(csr)])
            _run_ok(["openssl", "x509", "-req", "-in", str(csr), "-CA", str(self.ec_ca_cert), "-CAkey", str(self.ec_ca_key), "-CAcreateserial", "-days", "825", "-sha256", "-out", str(crt)])
            return crt.read_bytes()

    def _sign_account_token(self, blob: bytes) -> bytes:
        with tempfile.TemporaryDirectory() as td:
            tmp = Path(td)
            source = tmp / "token.bin"
            signature = tmp / "token.sig"
            source.write_bytes(blob)
            _run_ok(["openssl", "dgst", "-sha1", "-sign", str(self.rsa_ca_key), "-out", str(signature), str(source)])
            return signature.read_bytes()

    def mint_activation_record(self, activation_info: dict[str, Any]) -> dict[str, Any]:
        device_id = activation_info.get("DeviceID", {})
        device_info = activation_info.get("DeviceInfo", {})
        req_info = activation_info.get("ActivationRequestInfo", {})

        serial = str(device_id.get("SerialNumber", "UNKNOWN-SERIAL"))
        udid = str(device_id.get("UniqueDeviceID", "UNKNOWN-UDID"))

        account_token_obj = {
            "SerialNumber": serial,
            "UniqueDeviceID": udid,
            "ProductType": str(device_info.get("ProductType", "UnknownProduct")),
            "ActivationRandomness": str(req_info.get("ActivationRandomness", "UNKNOWN-RAND")),
            "IssuedAtUTC": dt.datetime.now(tz=dt.timezone.utc).isoformat(),
            "MimicProfile": self.profile,
            "PhoneNumberNotificationURL": "https://albert.apple.com/deviceservices/phoneHome",
            "ActivityURL": "https://albert.apple.com/deviceservices/activity",
        }
        account_token = json.dumps(account_token_obj, indent=2, sort_keys=True).encode()
        account_token_signature = self._sign_account_token(account_token)

        fairplay_raw = self.captured_record.get("FairPlayKeyData", b"-----BEGIN CONTAINER-----\n-----END CONTAINER-----\n")
        fairplay_seed = hashlib.sha256(account_token_signature + account_token).digest()
        fairplay_tail = base64.b64encode(fairplay_seed + os.urandom(48)).decode()
        fairplay_data = fairplay_raw + f"\n# MIMIC-SEED:{fairplay_tail}\n".encode()

        regulatory = json.dumps({"elabel": {"bis": {"regulatory": f"R-MIMIC-{serial[-6:] or '000000'}"}}}, separators=(",", ":")).encode()

        return {
            "unbrick": True,
            "AccountTokenCertificate": self._issue_rsa1024_cert("Apple iPhone Activation (Mimic)", "account_token"),
            "DeviceCertificate": self._issue_rsa1024_cert(serial, "device"),
            "RegulatoryInfo": regulatory,
            "FairPlayKeyData": fairplay_data,
            "AccountToken": account_token,
            "AccountTokenSignature": account_token_signature,
            "UniqueDeviceCertificate": self._issue_ecp256_cert("FDRDC-UCRT-SUBCA (Mimic)", "unique_device"),
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
CAPTURED_ACTIVATION_RECORD = _load_captured_activation_record()
CAPTURED_PROFILE = CapturedCryptoProfile(CAPTURED_ACTIVATION_RECORD)


class ActivationHandler(BaseHTTPRequestHandler):
    server_version = "Apple"
    sys_version = ""

    mint = MimicActivationMint(ROOT, CAPTURED_ACTIVATION_RECORD, CAPTURED_PROFILE)

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
