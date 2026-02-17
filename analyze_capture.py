#!/usr/bin/env python3
"""Extract protocol structure from captured iDevice activation traffic.

This tool is intentionally analysis-only and does not generate activation tickets.
"""

from __future__ import annotations

import base64
import json
import plistlib
import re
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parent


def _extract_data_block(text: str, key_name: str) -> bytes:
    m = re.search(rf"<key>{re.escape(key_name)}</key>\s*<data>\s*(.*?)\s*</data>", text, re.S)
    if not m:
        raise ValueError(f"Missing {key_name}")
    return base64.b64decode("".join(m.group(1).split()))


def _iter_capture_dirs() -> list[Path]:
    dirs: list[Path] = []
    for p in sorted(ROOT.iterdir()):
        if p.is_dir() and (p / "url.txt").exists():
            dirs.append(p)
    return dirs


def _load_handshake_response(path: Path) -> dict[str, Any]:
    raw = path.read_text()
    decoder = json.JSONDecoder()
    obj, _ = decoder.raw_decode(raw)
    return plistlib.loads(bytes(obj[str(i)] for i in range(len(obj))))


def analyze_handshake_dir(capture_dir: Path) -> dict[str, Any]:
    req_xml = (capture_dir / "handshake_request.xml").read_text()
    collection_blob = _extract_data_block(req_xml, "CollectionBlob")
    inner = plistlib.loads(collection_blob)
    resp_plist = _load_handshake_response(capture_dir / "handshake_response.json")
    return {
        "capture_dir": capture_dir.name,
        "request_fields": sorted(inner.keys()),
        "request_lengths": {
            "IngestBody": len(inner.get("IngestBody", b"")),
            "X-Apple-Sig-Key": len(inner.get("X-Apple-Sig-Key", b"")),
            "X-Apple-Signature": len(inner.get("X-Apple-Signature", b"")),
        },
        "response_fields": sorted(resp_plist.keys()),
        "response_lengths": {
            "serverKP": len(resp_plist.get("serverKP", b"")),
            "FDRBlob": len(resp_plist.get("FDRBlob", b"")),
            "SUInfo": len(resp_plist.get("SUInfo", b"")),
        },
    }


def analyze_activation_dir(capture_dir: Path) -> dict[str, Any]:
    req_text = (capture_dir / "deviceActivation_request.txt").read_text()
    activation_xml = _extract_data_block(req_text, "ActivationInfoXML")
    activation_plist = plistlib.loads(activation_xml)

    resp_html = (capture_dir / "deviceActivation_response.txt").read_text()
    m = re.search(r'<script id="protocol" type="text/x-apple-plist">\s*(<plist.*?</plist>)\s*</script>', resp_html, re.S)
    response_plist: dict[str, Any] = plistlib.loads(m.group(1).encode()) if m else {}
    root_key = next(iter(response_plist.keys()), None)
    root_payload = response_plist.get(root_key, {}) if root_key else {}

    return {
        "capture_dir": capture_dir.name,
        "request": {
            "transport": "multipart/form-data",
            "required_form_field": "activation-info",
            "activation_plist_fields": sorted(activation_plist.keys()),
            "device_identity": {
                k: activation_plist.get("DeviceInfo", {}).get(k)
                for k in ["ProductType", "ProductVersion", "BuildVersion", "DeviceClass", "ModelNumber"]
            },
        },
        "response": {
            "plist_root_fields": sorted(response_plist.keys()),
            "root_key": root_key,
            "root_payload_fields": sorted(root_payload.keys()) if isinstance(root_payload, dict) else [],
        },
    }


def main() -> None:
    handshakes = []
    activations = []
    for d in _iter_capture_dirs():
        if (d / "handshake_request.xml").exists() and (d / "handshake_response.json").exists():
            handshakes.append(analyze_handshake_dir(d))
        if (d / "deviceActivation_request.txt").exists() and (d / "deviceActivation_response.txt").exists():
            activations.append(analyze_activation_dir(d))

    report = {
        "endpoints": {
            "drmHandshake": "https://albert.apple.com/deviceservices/drmHandshake",
            "deviceActivation": "https://albert.apple.com/deviceservices/deviceActivation",
        },
        "captures_found": {
            "handshake": len(handshakes),
            "deviceActivation": len(activations),
        },
        "handshake_captures": handshakes,
        "device_activation_captures": activations,
        "limitations": [
            "Captured responses are cryptographically signed by Apple.",
            "This tool does not and cannot mint Apple-valid activation records.",
            "Use for interoperability research and lawful testing only.",
        ],
    }
    print(json.dumps(report, indent=2, default=str))


if __name__ == "__main__":
    main()
