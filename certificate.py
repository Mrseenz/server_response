#!/usr/bin/env python3
"""Extract signature and key material from captured activation certificates.

Reads the repository's captured activation record and handshake payload,
then writes a human-readable Markdown report to signing.md.
"""

from __future__ import annotations

import base64
import hashlib
import plistlib
import re
import subprocess
from pathlib import Path

ROOT = Path(__file__).resolve().parent


def _run(cmd: list[str]) -> str:
    result = subprocess.run(cmd, capture_output=True, text=True, check=False)
    if result.returncode != 0:
        raise RuntimeError(f"Command failed ({' '.join(cmd)}): {result.stderr.strip()}")
    return result.stdout


def _extract_data_block(text: str, key_name: str) -> bytes:
    match = re.search(rf"<key>{re.escape(key_name)}</key>\s*<data>\s*(.*?)\s*</data>", text, re.S)
    if not match:
        raise ValueError(f"Missing data block for {key_name}")
    return base64.b64decode("".join(match.group(1).split()))


def _load_handshake_info() -> dict[str, bytes]:
    req_xml = (ROOT / "4 handshake" / "handshake_request.xml").read_text()
    collection_blob = _extract_data_block(req_xml, "CollectionBlob")
    payload = plistlib.loads(collection_blob)

    sig_key = base64.b64decode(payload["X-Apple-Sig-Key"])
    signature = base64.b64decode(payload["X-Apple-Signature"])
    ingest_body = payload["IngestBody"]

    return {
        "sig_key": sig_key,
        "signature": signature,
        "ingest_body": ingest_body,
    }


def _load_activation_record() -> dict[str, bytes]:
    html = (ROOT / "2 deviceActivation" / "deviceActivation_response.txt").read_text()
    match = re.search(r'<script id="protocol" type="text/x-apple-plist">\s*(<plist.*?</plist>)\s*</script>', html, re.S)
    if not match:
        raise ValueError("Activation response plist was not found")
    payload = plistlib.loads(match.group(1).encode())
    return payload["ActivationRecord"]


def _parse_signature_block(cert_text: str) -> str:
    lines = cert_text.splitlines()
    chunks: list[str] = []
    capture = False
    for line in lines:
        stripped = line.rstrip()
        if stripped.strip() == "Signature Value:":
            capture = True
            continue
        if capture:
            if not stripped.startswith(" "):
                break
            chunks.append(stripped.strip())
    return "".join(chunks).replace(":", "")


def _cert_report(cert_name: str, pem_bytes: bytes, out_dir: Path) -> dict[str, str]:
    pem_path = out_dir / f"{cert_name}.pem"
    pem_path.write_bytes(pem_bytes)

    cert_text = _run(["openssl", "x509", "-in", str(pem_path), "-noout", "-text"])
    pubkey = _run(["openssl", "x509", "-in", str(pem_path), "-noout", "-pubkey"])
    subject = _run(["openssl", "x509", "-in", str(pem_path), "-noout", "-subject"]).strip()
    issuer = _run(["openssl", "x509", "-in", str(pem_path), "-noout", "-issuer"]).strip()

    signature_hex = _parse_signature_block(cert_text)

    sig_algo = "unknown"
    pub_algo = "unknown"
    pub_bits = "unknown"
    for line in cert_text.splitlines():
        stripped = line.strip()
        if stripped.startswith("Signature Algorithm:") and sig_algo == "unknown":
            sig_algo = stripped.split(":", 1)[1].strip()
        elif stripped.startswith("Public Key Algorithm:"):
            pub_algo = stripped.split(":", 1)[1].strip()
        elif stripped.startswith("Public-Key:"):
            pub_bits = stripped.split(":", 1)[1].strip().strip("()")

    return {
        "subject": subject,
        "issuer": issuer,
        "signature_algorithm": sig_algo,
        "public_key_algorithm": pub_algo,
        "public_key_bits": pub_bits,
        "signature_hex": signature_hex,
        "signature_sha256": hashlib.sha256(bytes.fromhex(signature_hex)).hexdigest() if signature_hex else "",
        "public_key_pem": pubkey.strip(),
        "public_key_sha256": hashlib.sha256(pubkey.encode()).hexdigest(),
        "pem_path": str(pem_path.relative_to(ROOT)),
    }


def build_signing_markdown() -> Path:
    out_dir = ROOT / "artifacts" / "signing"
    out_dir.mkdir(parents=True, exist_ok=True)

    handshake = _load_handshake_info()
    activation = _load_activation_record()

    cert_fields = [
        "AccountTokenCertificate",
        "DeviceCertificate",
        "UniqueDeviceCertificate",
    ]

    certs = {field: _cert_report(field, activation[field], out_dir) for field in cert_fields}

    account_signature = activation["AccountTokenSignature"]

    lines: list[str] = []
    lines.append("# Signing Artifacts")
    lines.append("")
    lines.append("Extracted from repository capture files (`4 handshake/*` and `2 deviceActivation/*`).")
    lines.append("")

    lines.append("## Handshake Signature + Key")
    lines.append(f"- `X-Apple-Sig-Key` length: **{len(handshake['sig_key'])} bytes**")
    lines.append(f"- `X-Apple-Sig-Key` SHA-256: `{hashlib.sha256(handshake['sig_key']).hexdigest()}`")
    lines.append(f"- `X-Apple-Signature` length: **{len(handshake['signature'])} bytes**")
    lines.append(f"- `X-Apple-Signature` SHA-256: `{hashlib.sha256(handshake['signature']).hexdigest()}`")
    lines.append(f"- `IngestBody` SHA-256: `{hashlib.sha256(handshake['ingest_body']).hexdigest()}`")
    lines.append("")

    lines.append("## Activation Record Account Token Signature")
    lines.append(f"- `AccountTokenSignature` length: **{len(account_signature)} bytes**")
    lines.append(f"- `AccountTokenSignature` SHA-256: `{hashlib.sha256(account_signature).hexdigest()}`")
    lines.append("")

    lines.append("## Certificate Signatures and Public Keys")
    lines.append("")

    for cert_name, info in certs.items():
        lines.append(f"### {cert_name}")
        lines.append(f"- Subject: `{info['subject']}`")
        lines.append(f"- Issuer: `{info['issuer']}`")
        lines.append(f"- Signature Algorithm: `{info['signature_algorithm']}`")
        lines.append(f"- Public Key Algorithm: `{info['public_key_algorithm']}`")
        lines.append(f"- Public Key Size: `{info['public_key_bits']}`")
        lines.append(f"- Certificate Signature SHA-256: `{info['signature_sha256']}`")
        lines.append(f"- Public Key SHA-256: `{info['public_key_sha256']}`")
        lines.append(f"- PEM file: `{info['pem_path']}`")
        lines.append("")
        lines.append("```pem")
        lines.append(info["public_key_pem"])
        lines.append("```")
        lines.append("")

    output_path = ROOT / "signing.md"
    output_path.write_text("\n".join(lines) + "\n")
    return output_path


def main() -> None:
    output = build_signing_markdown()
    print(f"Wrote signing report: {output}")


if __name__ == "__main__":
    main()
