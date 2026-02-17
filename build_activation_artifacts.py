#!/usr/bin/env python3
"""Build cryptographic artifacts from captured Apple activation traffic.

The goal is to materialize Apple-signed payloads into inspectable files so the
activation flow can be studied offline.
"""

from __future__ import annotations

import argparse
import base64
import hashlib
import json
import plistlib
import re
import subprocess
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parent


def _extract_data_block(text: str, key_name: str) -> bytes:
    m = re.search(rf"<key>{re.escape(key_name)}</key>\s*<data>\s*(.*?)\s*</data>", text, re.S)
    if not m:
        raise ValueError(f"Missing {key_name}")
    b64 = "".join(m.group(1).split())
    return base64.b64decode(b64)


def _load_handshake_request() -> dict[str, Any]:
    req_xml = (ROOT / "4 handshake" / "handshake_request.xml").read_text()
    collection_blob = _extract_data_block(req_xml, "CollectionBlob")
    return plistlib.loads(collection_blob)


def _load_activation_record() -> dict[str, Any]:
    resp_html = (ROOT / "2 deviceActivation" / "deviceActivation_response.txt").read_text()
    m = re.search(r'<script id="protocol" type="text/x-apple-plist">\s*(<plist.*?</plist>)\s*</script>', resp_html, re.S)
    if not m:
        raise ValueError("Could not find activation response plist")
    response_plist = plistlib.loads(m.group(1).encode())
    return response_plist["ActivationRecord"]


def _openssl_x509_summary(pem_path: Path) -> str:
    result = subprocess.run(
        ["openssl", "x509", "-in", str(pem_path), "-noout", "-subject", "-issuer", "-dates", "-serial", "-fingerprint", "-sha256"],
        capture_output=True,
        text=True,
        check=False,
    )
    if result.returncode != 0:
        return f"OPENSSL_PARSE_ERROR\n{result.stderr.strip()}"
    return result.stdout.strip()


def build_artifacts(out_dir: Path) -> Path:
    out_dir.mkdir(parents=True, exist_ok=True)

    handshake = _load_handshake_request()
    activation_record = _load_activation_record()

    # --- Handshake signing material ------------------------------------------------
    ingest_body: bytes = handshake["IngestBody"]
    sig_key_b64: str = handshake["X-Apple-Sig-Key"]
    signature_b64: str = handshake["X-Apple-Signature"]

    sig_key_raw = base64.b64decode(sig_key_b64)
    signature_raw = base64.b64decode(signature_b64)

    (out_dir / "handshake_ingest_body.json").write_bytes(ingest_body)
    (out_dir / "handshake_sig_key.bin").write_bytes(sig_key_raw)
    (out_dir / "handshake_signature.der").write_bytes(signature_raw)

    # --- Activation record material ------------------------------------------------
    cert_fields = [
        "AccountTokenCertificate",
        "DeviceCertificate",
        "UniqueDeviceCertificate",
    ]
    cert_summaries: dict[str, str] = {}

    for field in cert_fields:
        pem_bytes = activation_record[field]
        pem_path = out_dir / f"{field}.pem"
        pem_path.write_bytes(pem_bytes)
        cert_summaries[field] = _openssl_x509_summary(pem_path)

    # FairPlayKeyData is delivered as a signed "CONTAINER" PEM block.
    fairplay_pem = activation_record["FairPlayKeyData"]
    (out_dir / "FairPlayKeyData.pem").write_bytes(fairplay_pem)

    # Account token + signature are the user/account binding artifacts.
    account_token_raw = activation_record["AccountToken"]
    account_token_signature_raw = activation_record["AccountTokenSignature"]
    (out_dir / "AccountToken.json").write_bytes(account_token_raw)
    (out_dir / "AccountTokenSignature.bin").write_bytes(account_token_signature_raw)

    token_pretty_path = out_dir / "AccountToken.pretty.json"
    try:
        token_obj = json.loads(account_token_raw.decode())
        token_pretty_path.write_text(json.dumps(token_obj, indent=2, sort_keys=True))
    except Exception:
        token_pretty_path.write_text("<failed to parse account token as JSON>")

    report = {
        "handshake": {
            "ingest_body_bytes": len(ingest_body),
            "ingest_body_sha256": hashlib.sha256(ingest_body).hexdigest(),
            "x_apple_sig_key_format": "SEC1 uncompressed EC point (expected 65 bytes for P-256)",
            "x_apple_sig_key_bytes": len(sig_key_raw),
            "x_apple_signature_format": "DER ECDSA signature",
            "x_apple_signature_bytes": len(signature_raw),
            "verification_note": "Captured key/signature artifacts were exported for offline verification against IngestBody.",
        },
        "activation_record": {
            "fields": sorted(activation_record.keys()),
            "account_token_bytes": len(account_token_raw),
            "account_token_sha256": hashlib.sha256(account_token_raw).hexdigest(),
            "account_token_signature_bytes": len(account_token_signature_raw),
            "account_token_signature_sha256": hashlib.sha256(account_token_signature_raw).hexdigest(),
            "certificate_summaries": cert_summaries,
            "fairplay_key_data_note": "FairPlayKeyData uses Apple 'CONTAINER' PEM framing and is not a plain X.509 certificate.",
        },
        "output_directory": str(out_dir.relative_to(ROOT)),
    }

    (out_dir / "crypto_report.json").write_text(json.dumps(report, indent=2))
    return out_dir


def main() -> None:
    parser = argparse.ArgumentParser(description="Extract Apple-signed activation cryptographic artifacts")
    parser.add_argument("--output-dir", default=str(ROOT / "artifacts" / "apple_crypto"), help="Directory to write extracted artifacts")
    args = parser.parse_args()

    out_dir = Path(args.output_dir)
    final_dir = build_artifacts(out_dir)
    print(f"Wrote activation cryptographic artifacts to: {final_dir}")


if __name__ == "__main__":
    main()
